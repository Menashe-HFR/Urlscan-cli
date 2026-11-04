"""Optional third-party page images with explicit provenance and graceful quota handling."""
from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from .inspection import is_public, resolve_public, validate_target


def safe_image(value):
    try:
        parsed=urlsplit(value)
        host=parsed.hostname or ''
        return parsed.scheme=='https' and not parsed.username and not parsed.password and parsed.port in (None,443) and (
            host.endswith('.microlink.io') or host=='microlink-cdn.s3.amazonaws.com')
    except (ValueError,TypeError):
        return False


async def _capture(url,client):
    retrieved=datetime.now(timezone.utc).isoformat()
    key=os.getenv('MICROLINK_API_KEY','').strip()
    headers={'x-api-key':key} if key else {}
    reason='The screenshot provider did not return an image.'
    try:
        response=await client.get('https://api.microlink.io/',params={'url':url,'screenshot':'true','meta':'false'},headers=headers,timeout=15)
        if response.status_code==200:
            data=response.json()
            image=(data.get('data') or {}).get('screenshot') or {}
            if data.get('status')=='success' and safe_image(image.get('url')):
                return {'status':'available','url':image['url'],'source':'Microlink','kind':'provider',
                    'retrieved_at':retrieved,'captured_at':None,'width':image.get('width'),'height':image.get('height'),
                    'note':'Provider screenshot; it may be cached. Capture time was not supplied by the provider.'}
        elif response.status_code==429:
            reason='The screenshot provider quota is currently exhausted.'
    except (httpx.HTTPError,ValueError,AttributeError,TypeError):
        reason='The screenshot provider was unavailable.'
    # An older observation is useful only when its source and scan date stay explicit.
    try:
        response=await client.get('https://urlscan.io/api/v1/search/',params={'q':'page.url:'+json.dumps(url)+' AND date:>now-90d','size':5},timeout=8)
        if response.status_code==200:
            for item in response.json().get('results',[]):
                observed=(item.get('page') or {}).get('url')
                try:
                    if validate_target(observed)!=url:
                        continue
                    scan_id=str(uuid.UUID(item.get('_id','')))
                except (ValueError,TypeError,AttributeError):
                    continue
                scanned=(item.get('task') or {}).get('time')
                return {'status':'available','url':f'https://urlscan.io/screenshots/{scan_id}.png',
                    'source':'urlscan.io archive','kind':'archived','retrieved_at':retrieved,'captured_at':scanned,
                    'report_url':f'https://urlscan.io/result/{scan_id}/',
                    'note':'Archived public scan. This image is not a new capture and may differ from the current page.'}
    except (httpx.HTTPError,ValueError,AttributeError,TypeError):
        pass
    return {'status':'unavailable','url':None,'source':None,'note':reason+' No matching archived image was available. HTTP findings are unaffected.'}


async def capture_preview(value,*,client=None,resolver=resolve_public):
    try:
        url=validate_target(value)
        parts=urlsplit(url)
        addresses=await resolver(parts.hostname,parts.port or (443 if parts.scheme=='https' else 80))
        if not addresses or any(not is_public(address) for address in addresses):
            raise ValueError('Only public targets can be sent to screenshot providers.')
        async with asyncio.timeout(25):
            if client is not None:
                return await _capture(url,client)
            async with httpx.AsyncClient(follow_redirects=False,trust_env=False) as connection:
                return await _capture(url,connection)
    except (ValueError,TimeoutError,OSError):
        return {'status':'unavailable','url':None,'source':None,'note':'A screenshot could not be obtained for this public URL. HTTP findings are unaffected.'}
