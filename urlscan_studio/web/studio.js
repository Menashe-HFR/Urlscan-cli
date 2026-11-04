'use strict';
(() => {
  const $=selector=>document.querySelector(selector);
  const escape=value=>String(value??'—').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
  const labels={no_flags:'No flags',review:'Review',malicious:'Flagged',unknown:'Unknown',failed:'Scan failed',cancelled:'Cancelled',queued:'Queued',running:'Inspecting'};
  const active=job=>job&&['queued','running'].includes(job.status);
  const apiBase=$('meta[name="api-base"]').content;
  let cloud=false,cloudRun=null,formSequence=0,openedResult=null;
  const previewQueue=[];let previewBusy=0;
  let samples,current,config={provider:'demo',synthetic:true},filter='all',query='',toastTimer,pollTimer,controller,opener;
  const history=new Map(),cache=new Map();
  const time=()=>Date.now()/1000;
  const clone=value=>JSON.parse(JSON.stringify(value));
  const formatTime=value=>new Date(value*1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
  const setText=(selector,value)=>{$(selector).textContent=value;};
  function toast(message){clearTimeout(toastTimer);setText('#toast',message);$('#toast').hidden=false;toastTimer=setTimeout(()=>{$('#toast').hidden=true;},3500);}
  async function api(path,options={}){
    const response=await fetch(apiBase+path,{...options,headers:{'Content-Type':'application/json',...options.headers},signal:options.signal||AbortSignal.timeout(12000)});
    if(!response.ok){let message=`Request failed (HTTP ${response.status})`;try{const data=await response.json();message=typeof data.detail==='string'?data.detail:message;}catch{}throw Error(message);}
    return response.json();
  }
  function event(job,message){job.events.push({at:time(),message,seq:job.events.length+1});}
  function resultLabel(item){return item.status==='completed'?(item.result?.verdict||'unknown'):item.status;}
  function badge(label){return `<span class="verdict ${escape(label)}"><span aria-hidden="true">${label==='no_flags'?'✓':label==='malicious'?'!':label==='review'?'◈':'·'}</span>${escape(labels[label]||label)}</span>`;}
  function snapshot(){
    const job={id:'sample-preview',name:samples.name,provider:'demo',visibility:'private',status:'completed_with_errors',created:time(),duplicates:0,events:[],items:[]};
    job.items=samples.urls.map((url,index)=>({id:`sample-${index}`,url,status:index===5?'failed':'completed',cached:false,result:index===5?null:clone(samples.results[new URL(url).hostname]),error:index===5?'Synthetic scenario: the upstream result timed out. Unknown is not a clean verdict.':null}));
    event(job,'Sample investigation loaded. All evidence is synthetic; no websites were contacted.');
    event(job,'5 observations available · 1 unavailable scan kept visible as unknown.');
    return job;
  }
  function render(){
    if(!current)return;
    if(cloud)saveHistory();
    const counts={no_flags:0,review:0,malicious:0,unknown:0};
    current.items.forEach(item=>{const label=resultLabel(item);counts[label in counts?label:'unknown']++;});
    const done=current.items.filter(item=>['completed','failed','cancelled'].includes(item.status)).length;
    setText('#batch-title',current.name);setText('#metric-total',String(current.items.length).padStart(2,'0'));setText('#metric-clear',String(counts.no_flags).padStart(2,'0'));setText('#metric-review',String(counts.review).padStart(2,'0'));setText('#metric-flagged',String(counts.malicious).padStart(2,'0'));setText('#metric-unknown',String(counts.unknown).padStart(2,'0'));
    setText('#all-count',current.items.length);setText('#metric-total-note',active(current)?`${done} observations returned`:`${done} outcomes recorded`);
    setText('#provenance',current.provider==='demo'?'SYNTHETIC DATA':current.provider==='live-http'?'LIVE HTTP EVIDENCE':'URLSCAN.IO OBSERVATIONS');
    setText('#batch-subtitle',`${current.items.length} URLs · ${current.provider==='demo'?'Fictional dataset':current.provider==='live-http'?'Live HTTP inspection':current.visibility+' visibility'} · ${current.duplicates||0} duplicates removed`);
    $('#batch-progress').hidden=!active(current);$('#cancel-batch').hidden=!active(current);$('#retry-batch').hidden=current.status!=='completed_with_errors'||current.id==='sample-preview';
    setText('#progress-label',cloud?'Collecting HTTP evidence · up to 24 seconds…':current.status==='queued'?'Waiting for a worker…':'Inspecting URLs with bounded concurrency…');setText('#progress-count',`${done} / ${current.items.length}`);$('#progress-bar').style.width=`${done/Math.max(1,current.items.length)*100}%`;
    const items=current.items.filter(item=>(filter==='all'||(filter==='unknown'?['unknown','failed','cancelled'].includes(resultLabel(item)):resultLabel(item)===filter))&&item.url.toLowerCase().includes(query));
    $('#results-body').innerHTML=items.map(item=>{
      const r=item.result||{},url=new URL(item.url),label=resultLabel(item);
      return `<tr><td><div class="domain-cell"><span class="domain-icon" aria-hidden="true">${escape(url.hostname.slice(0,1).toUpperCase())}</span><div><button type="button" class="domain-button" data-result="${escape(item.id)}">${escape(url.hostname)}</button>${item.cached?'<span class="cache-mark">CACHED</span>':''}<span class="url-path">${escape(url.pathname+url.search+url.hash)}</span></div></div></td><td>${badge(label)}</td><td>${escape(r.http_status)}</td><td>${escape(r.request_count)}</td><td><span class="country">${escape(r.source==='live-http'?`${r.duration_ms} ms`:r.country)}</span></td><td><button type="button" class="row-open" data-result="${escape(item.id)}" aria-label="Inspect ${escape(url.hostname)}">↗</button></td></tr>`;
    }).join('')||'<tr><td class="empty-table" colspan="6">No URLs match this view. Try another filter or search.</td></tr>';
    setText('#result-count',`Showing ${items.length} of ${current.items.length} URLs`);
    setText('#run-state',current.id==='sample-preview'?'Sample investigation ready':current.status==='completed_with_errors'?'Finished with errors':current.status==='completed'?'Investigation complete':current.status==='cancelled'?'Run cancelled':`${done} / ${current.items.length} processed`);
    setText('#activity-state',active(current)?'WORKER ACTIVE':'ALL SYSTEMS QUIET');
    $('#activity-list').innerHTML=current.events.slice(-5).map(e=>`<li><time>${formatTime(e.at)}</time>${escape(e.message)}</li>`).join('');
    setText('#history-count',Math.max(1,history.size));
    $('.filters').querySelectorAll('button').forEach(button=>{const selected=button.dataset.filter===filter;button.classList.toggle('selected',selected);button.setAttribute('aria-pressed',String(selected));});
    if(!$('#view-history').hidden)renderHistory();
    renderPreviews();
  }
  function normalizeInput(value){
    if(value.length>2048||/[\s\x00-\x1f\x7f]/.test(value))throw Error('URLs must not contain spaces or control characters.');
    let url;try{url=new URL(value.includes('://')?value:`https://${value}`);}catch{throw Error('Enter a valid URL on each line.');}
    if(!['https:','http:'].includes(url.protocol)||url.username||url.password||!url.hostname.includes('.')||url.hostname.endsWith('.local'))throw Error('Use HTTP(S) URLs with public hostnames and no credentials.');
    url.hostname=url.hostname.toLowerCase().replace(/\.$/,'');return url.href;
  }
  function prepareInput(value){const lines=value.split(/\r?\n/).map(line=>line.trim()).filter(Boolean);if(lines.length<1||lines.length>100)throw Error('Enter between 1 and 100 URLs.');const urls=lines.map(normalizeInput);return {urls:[...new Set(urls)],duplicates:urls.length-new Set(urls).size,original:urls};}
  function fillSamples(){if(cloud)$('#inspection-mode').value='sample';setText('#form-error','');$('#form-error').hidden=true;$('#batch-urls').value=samples.urls.join('\n');$('#batch-name').value=samples.name;}
  function openBatch(){formSequence++;$('#submit-batch').disabled=false;$('#form-error').hidden=true;opener=document.activeElement;$('#batch-dialog').showModal();$('#batch-name').focus();}
  function unknown(url){return {source:'synthetic',verdict:'unknown',score:null,title:'Custom URL in demo mode',request_count:0,domains:[],requests:[],redirects:[],findings:[{severity:'info',title:'This URL was not scanned',detail:'Demo mode makes no external requests. Use sample URLs or run the Python service with the live provider.'}],final_url:url};}
  async function simulate(job,signal,onlyFailed=false){
    job.status='running';event(job,onlyFailed?'Retrying failed items in this simulated session.':'Demo worker started · 3 concurrent slots.');
    const queued=job.items.filter(item=>onlyFailed?item.status==='failed':item.status==='queued');
    queued.forEach(item=>{item.status='queued';item.error=null;});
    let next=0;
    async function worker(){
      while(next<queued.length&&!signal.aborted){
        const item=queued[next++];item.status='running';event(job,`Inspecting ${new URL(item.url).hostname}`);if(current.id===job.id)render();
        await new Promise(resolve=>{const id=setTimeout(resolve,650+next*120);signal.addEventListener('abort',()=>{clearTimeout(id);resolve();},{once:true});});
        if(signal.aborted)return;
        const host=new URL(item.url).hostname;
        if(host==='offline.test'){item.status='failed';item.error='Synthetic upstream timeout. No external request was made.';event(job,`Unavailable: ${host} · kept as unknown.`);}
        else{item.status='completed';item.cached=cache.has(item.url);item.result=clone(cache.get(item.url)||samples.results[host]||unknown(item.url));cache.set(item.url,item.result);event(job,`${item.cached?'Demo cache hit':'Completed'}: ${host} → ${labels[item.result.verdict]}`);}
        if(current.id===job.id)render();
      }
    }
    await Promise.all(Array.from({length:Math.min(3,queued.length)},worker));
    if(!signal.aborted){job.status=job.items.some(item=>item.status==='failed')?'completed_with_errors':'completed';event(job,'Demo run finished. JSON and CSV exports are ready.');}
    if(current.id===job.id)render();setText('#live-status',`Investigation ${job.status.replaceAll('_',' ')}.`);
  }
  async function submit(urls,name,duplicates=0,original=urls,mode='live',withPreview=true){
    if((cloud&&cloudRun)||active(current))throw Error('Finish or cancel the current run before starting another.');
    filter='all';query='';$('#search-results').value='';clearTimeout(pollTimer);
    if(cloud){
      if(mode==='live'&&urls.length>5)throw Error('Use at most five URLs per live inspection.');
      current={id:crypto.randomUUID(),name,provider:mode==='sample'?'demo':'live-http',visibility:'not-applicable',status:'running',created:time(),duplicates,items:urls.map(url=>({id:crypto.randomUUID(),url,status:'running',result:null,error:null,cached:false})),events:[]};
      history.set(current.id,current);event(current,mode==='sample'?'Requesting a labeled sample test from the API.':'Requesting public HTTP evidence from the Python API.');
      const pendingId=current.id;const run={id:pendingId,job:current,controller:new AbortController()};cloudRun=run;render();setView('workspace');if($('#batch-dialog').open)$('#batch-dialog').close();
      try{
        const job=await api('/inspect',{method:'POST',body:JSON.stringify({urls:original,name,mode}),signal:run.controller.signal});
        history.delete(pendingId);job.screenshots_requested=mode==='live'&&withPreview;history.set(job.id,job);if(current.id===pendingId)current=job;if(job.screenshots_requested)schedulePreviews(job);render();setText('#live-status',`Inspection finished. ${job.done} outcomes recorded.`);
        toast(mode==='sample'?'Sample test returned labeled synthetic results.':'HTTP inspection finished. Open a URL for evidence and recommendations.');
      }catch(error){
        if(error.name==='AbortError')return;
        run.job.status='completed_with_errors';run.job.items.forEach(item=>{item.status='failed';item.error=error.message;});event(run.job,error.message);render();throw error;
      }finally{if(cloudRun===run)cloudRun=null;}
      return;
    }
    if(apiBase){const response=await api('/jobs',{method:'POST',headers:{'Idempotency-Key':crypto.randomUUID()},body:JSON.stringify({urls:original,name,visibility:$('#scan-visibility').value})});current=await api(`/jobs/${response.id}`);history.set(current.id,current);poll(current.id);}
    else{
      current={id:crypto.randomUUID(),name,provider:'demo',visibility:'private',status:'queued',created:time(),duplicates,items:urls.map(url=>({id:crypto.randomUUID(),url,status:'queued',result:null,error:null,cached:false})),events:[]};
      history.set(current.id,current);event(current,`Queued ${urls.length} unique URLs; removed ${duplicates} duplicates.`);controller=new AbortController();simulate(current,controller.signal).catch(error=>{toast(error.message);});
    }
    render();setView('workspace');setText('#live-status','Investigation started.');
  }
  async function poll(id){
    try{const job=await api(`/jobs/${id}`);history.set(id,job);if(current.id===id){current=job;render();if(active(job))pollTimer=setTimeout(()=>poll(id),700);else setText('#live-status',`Investigation ${job.status.replaceAll('_',' ')}.`);}}
    catch(error){toast(error.message+' Open run history to reconnect.');}
  }
  async function cancel(){
    try{if(cloud){const run=cloudRun;if(!run||run.id!==current.id)return;run.controller.abort();cloudRun=null;run.job.status='cancelled';run.job.items.filter(i=>['queued','running'].includes(i.status)).forEach(i=>{i.status='cancelled';});event(run.job,'Stopped waiting locally. The server may finish already-started HTTP requests.');render();toast('Stopped waiting. Already-started server requests may finish.');return;}if(apiBase){current=await api(`/jobs/${current.id}/cancel`,{method:'POST'});}else{controller?.abort();current.status='cancelled';current.items.filter(i=>['queued','running'].includes(i.status)).forEach(i=>{i.status='cancelled';});event(current,'Run cancelled. Completed observations have been preserved.');}history.set(current.id,current);render();toast('Run cancelled. Completed results are still here.');}catch(error){toast(error.message);}
  }
  async function retry(){
    try{if(cloud){await submit(current.items.filter(i=>i.status==='failed').map(i=>i.url),current.name+' · retry',0,undefined,current.provider==='demo'?'sample':'live');return;}if(apiBase){await api(`/jobs/${current.id}/retry`,{method:'POST'});current=await api(`/jobs/${current.id}`);poll(current.id);}else{controller=new AbortController();simulate(current,controller.signal,true).catch(error=>toast(error.message));}render();}catch(error){toast(error.message);}
  }
  function download(content,type,name){const url=URL.createObjectURL(new Blob([content],{type})),link=document.createElement('a');link.href=url;link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
  function exportReport(format){
    if(apiBase&&!cloud&&current.id!=='sample-preview'){const link=document.createElement('a');link.href=`${apiBase}/jobs/${current.id}/export?format=${format}`;link.download=`investigation.${format}`;link.click();return;}
    if(format==='json')download(JSON.stringify(current,null,2),'application/json',cloud?'inspection.json':'investigation-demo.json');
    else{
      const rows=[['url','state','verdict','score','http_status','country','source','cached','error','checks_passed','checks_total','duration_ms'],...current.items.map(item=>{const r=item.result||{};return[item.url,item.status,r.verdict||'unknown',r.score,r.http_status,r.country,r.source||current.provider,Boolean(item.cached),item.error,r.posture?.passed,r.posture?.total,r.duration_ms];})];
      const cell=value=>{let text=String(value??'');if(/^[\s]*[=+@-]/.test(text))text="'"+text;return '"'+text.replaceAll('"','""')+'"';};download(rows.map(row=>row.map(cell).join(',')).join('\r\n'),'text/csv',cloud?'inspection.csv':'investigation-demo.csv');
    }toast('Report exported with its data source included.');
  }
  function detail(item){
    openedResult={jobId:current.id,itemId:item.id};
    const r=item.result||{},host=new URL(item.url).hostname,verdict=resultLabel(item),source=r.source||current.provider;
    const facts=r.source==='live-http'?[['HTTP RESPONSE',r.http_status],['RESPONSE TIME',`${r.duration_ms} ms`],['BASELINE CHECKS',`${r.posture?.passed} / ${r.posture?.total}`],['FINAL DESTINATION',r.final_url],['RESULT SOURCE','Live HTTP response']]:[['HTTP RESPONSE',r.http_status],['COUNTRY / IP',[r.country,r.ip].filter(Boolean).join(' · ')||'—'],['NETWORK',r.asn],['TLS VALIDITY PERIOD',r.tls_days!=null?`${r.tls_days} days (not time remaining)`:'—'],['REQUESTS OBSERVED',r.request_count],['RESULT SOURCE',source==='synthetic'?'Synthetic demo fixture':source]];
    $('#detail-content').innerHTML=`<header class="detail-top"><div><p class="eyebrow">RESULT INSPECTOR / ${source==='synthetic'?'SYNTHETIC DATA':source==='live-http'?'LIVE HTTP RESPONSE':'PROVIDER OBSERVATION'}</p><h2 id="detail-heading">${escape(host)}</h2><p>${escape(item.url)}</p></div><button type="button" class="close-button" data-close="detail-dialog" aria-label="Close result inspector">×</button></header><div class="detail-grid"><aside class="detail-summary"><h3>THE OBSERVATION</h3>${badge(verdict)}<div class="detail-score">${r.posture?`${r.posture.passed}<small> / ${r.posture.total} checks passed</small>`:`${escape(r.score)}<small> provider score</small>`}</div><dl>${facts.map(([name,value])=>`<div><dt>${name}</dt><dd>${escape(value)}</dd></div>`).join('')}</dl><p class="source-note">${source==='synthetic'?'Fictional .test domain and documentation-only IPs. No site was scanned.':r.source==='live-http'?escape(r.scope):'A point-in-time provider observation. No flags is not a guarantee of safety.'}</p></aside><div class="detail-main"><div class="detail-tabs" role="tablist" aria-label="Result evidence"><button role="tab" id="tab-findings" aria-selected="true" aria-controls="evidence-findings" data-tab="findings">Findings</button><button role="tab" id="tab-domains" aria-selected="false" aria-controls="evidence-domains" data-tab="domains" tabindex="-1">Domains</button><button role="tab" id="tab-requests" aria-selected="false" aria-controls="evidence-requests" data-tab="requests" tabindex="-1">Requests</button>${current.provider==='live-http'?'<button role="tab" id="tab-screenshot" aria-selected="false" aria-controls="evidence-screenshot" data-tab="screenshot" tabindex="-1">Screenshot</button>':''}${r.headers?'<button role="tab" id="tab-headers" aria-selected="false" aria-controls="evidence-headers" data-tab="headers" tabindex="-1">Headers</button>':''}</div><section id="evidence-findings" role="tabpanel" aria-labelledby="tab-findings">${r.summary?`<p class="inspection-summary">${escape(r.summary)}</p>`:''}${item.error?`<div class="detail-error">${escape(item.error)}</div>`:(r.findings||[]).map(finding=>`<article class="finding ${escape(finding.severity)}"><span aria-hidden="true">${finding.severity==='high'?'!':finding.severity==='medium'?'◈':'✓'}</span><div><h3>${escape(finding.title)}</h3><p>${escape(finding.detail)}</p></div></article>`).join('')||'<p>No evidence is available yet.</p>'}${r.redirects?.length?`<div class="request-entry"><small>NAVIGATION CHANGE</small>${r.redirects.map(escape).join(' → ')}</div>`:''}</section><section id="evidence-domains" role="tabpanel" aria-labelledby="tab-domains" hidden>${(r.domains||[]).map(domain=>`<div class="network-row"><span>${escape(domain.domain)}<small> ${domain.third_party?'other host':'page host'}</small></span><span class="network-bar"><i style="width:${Math.max(5,Math.min(100,Number(domain.requests??domain.references??0)/Math.max(1,r.request_count||1)*100))}%"></i></span><b>${escape(domain.requests??domain.references)}<small> ${domain.observed===false?'refs':''}</small></b></div>`).join('')||'<p class="field-note">No domain evidence available.</p>'}<p class="field-note">Other host means a different hostname, not necessarily a different owner. For live HTTP checks, HTML resource references are listed but never loaded.</p></section><section id="evidence-requests" role="tabpanel" aria-labelledby="tab-requests" hidden>${(r.requests||[]).map(request=>`<div class="request-entry"><small>${escape(request.method)} · ${escape(request.type)} · HTTP ${escape(request.status)}</small>${escape(request.url)}</div>`).join('')||'<p class="field-note">No request evidence available.</p>'}</section>${r.headers?`<section id="evidence-headers" role="tabpanel" aria-labelledby="tab-headers" hidden>${(r.checks||[]).map(check=>`<div class="check-row"><span class="${check.passed?'check-pass':'check-missing'}">${check.passed?'✓':'○'}</span><strong>${escape(check.label)}</strong><small>${check.passed?'Observed':'Review'}</small></div>`).join('')}<h3 class="header-heading">Observed response headers</h3>${Object.entries(r.headers).map(([key,value])=>`<div class="request-entry"><small>${escape(key)}</small><code>${escape(value)}</code></div>`).join('')||'<p class="field-note">None of the inspected headers was present.</p>'}</section>`:''}${current.provider==='live-http'?`<section id="evidence-screenshot" role="tabpanel" aria-labelledby="tab-screenshot" hidden>${previewHTML(item,true)}</section>`:''}</div></div><footer class="detail-bottom"><span>${item.cached?'Reused from cache':'Evidence is preserved with this investigation'}</span>${r.report_url&&/^https:\/\/urlscan\.io\/result\/[\da-f-]+\/$/.test(r.report_url)?`<a href="${escape(r.report_url)}" target="_blank" rel="noopener noreferrer">Open provider report ↗</a>`:r.source==='live-http'?'<span>Live HTTP evidence · limited scope</span>':'<span>Demo evidence · for exploration</span>'}</footer>`;
    opener=document.activeElement;$('#detail-dialog').showModal();
  }
  function selectTab(name){$('#detail-dialog').querySelectorAll('[role=tab]').forEach(tab=>{const selected=tab.dataset.tab===name;tab.setAttribute('aria-selected',String(selected));tab.tabIndex=selected?0:-1;$(`#evidence-${tab.dataset.tab}`).hidden=!selected;});}
  async function renderHistory(){
    let jobs=[...history.values()].reverse();
    if(apiBase&&!cloud){try{jobs=(await api('/jobs')).jobs;}catch(error){toast(error.message);}}
    $('#history-list').innerHTML=jobs.map(job=>`<article class="history-card"><div><h2>${escape(job.name)}</h2><p>${escape(job.provider==='demo'?'Synthetic demo':job.provider==='live-http'?'Live HTTP evidence':'urlscan.io')} · ${escape(job.status.replaceAll('_',' '))} · ${job.items?.length??job.total} URLs · ${new Date(job.created*1000).toLocaleString()}</p></div><button type="button" data-history="${escape(job.id)}">Open run ↗</button></article>`).join('')||'<p>No saved runs yet. Start an investigation to create one.</p>';
  }
  function setView(name){document.querySelectorAll('.view').forEach(view=>{view.hidden=view.id!==`view-${name}`;});document.querySelectorAll('[data-view]').forEach(button=>{const selected=button.dataset.view===name;button.classList.toggle('active',selected);selected?button.setAttribute('aria-current','page'):button.removeAttribute('aria-current');});setText('#view-name',{workspace:'Investigations',history:'Run history',architecture:'Under the hood'}[name]);if(name==='history')renderHistory();}
  document.addEventListener('click',async event=>{
    const close=event.target.closest('[data-close]');if(close){$(`#${close.dataset.close}`).close();return;}
    const preview=event.target.closest('[data-preview-open]');if(preview){detail(current.items.find(item=>item.id===preview.dataset.previewOpen));selectTab('screenshot');return;}
    const row=event.target.closest('[data-result]');if(row){detail(current.items.find(item=>item.id===row.dataset.result));return;}
    const tab=event.target.closest('[data-tab]');if(tab){selectTab(tab.dataset.tab);return;}
    const view=event.target.closest('[data-view]');if(view){setView(view.dataset.view);return;}
    const previous=event.target.closest('[data-history]');if(previous){try{clearTimeout(pollTimer);current=apiBase&&!cloud?await api(`/jobs/${previous.dataset.history}`):history.get(previous.dataset.history);filter='all';query='';$('#search-results').value='';render();setView('workspace');if(apiBase&&!cloud&&active(current))poll(current.id);}catch(error){toast(error.message);}}
  });
  $('#detail-dialog').addEventListener('keydown',event=>{if(!event.target.matches('[role=tab]')||!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;event.preventDefault();const tabs=[...$('#detail-dialog').querySelectorAll('[role=tab]')],index=tabs.indexOf(event.target),next=event.key==='Home'?0:event.key==='End'?tabs.length-1:(index+(event.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;selectTab(tabs[next].dataset.tab);tabs[next].focus();});
  document.querySelectorAll('dialog').forEach(dialog=>{dialog.addEventListener('close',()=>opener?.isConnected&&opener.focus());dialog.addEventListener('click',event=>{if(event.target!==dialog)return;const r=dialog.getBoundingClientRect();if(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom)dialog.close();});});
  $('.filters').addEventListener('click',event=>{const button=event.target.closest('[data-filter]');if(button){filter=button.dataset.filter;render();}});
  $('#search-results').addEventListener('input',event=>{query=event.target.value.toLowerCase();render();});
  $('#run-live-test').addEventListener('click',async()=>{try{await submit(['https://www.python.org/'],'Live test · python.org',0,['https://www.python.org/'],'live');}catch(error){toast(error.message);}});
  $('#new-batch').addEventListener('click',openBatch);$('#load-samples').addEventListener('click',fillSamples);
  $('#run-sample').addEventListener('click',async()=>{try{await submit(samples.urls,samples.name,0,samples.urls,'sample');}catch(error){toast(error.message);}});
  $('#batch-form').addEventListener('submit',async event=>{event.preventDefault();$('#form-error').hidden=true;const button=$('#submit-batch'),token=++formSequence;button.disabled=true;try{const prepared=prepareInput($('#batch-urls').value),name=$('#batch-name').value.trim();if(!name)throw Error('Give this investigation a name.');await submit(prepared.urls,name,prepared.duplicates,prepared.original,cloud?$('#inspection-mode').value:'live',!cloud||$('#dialog-screenshot').checked);if(token===formSequence)$('#batch-dialog').close();}catch(error){if(token===formSequence){setText('#form-error',error.message);$('#form-error').hidden=false;if(!$('#batch-dialog').open)toast(error.message);}}finally{if(token===formSequence)button.disabled=false;}});
  $('#cancel-batch').addEventListener('click',cancel);$('#retry-batch').addEventListener('click',retry);$('#export-csv').addEventListener('click',()=>exportReport('csv'));$('#export-json').addEventListener('click',()=>exportReport('json'));
  document.addEventListener('visibilitychange',()=>{if(document.hidden)clearTimeout(pollTimer);else if(apiBase&&!cloud&&active(current))poll(current.id);});
  function safePreviewURL(value){try{const url=new URL(value),host=url.hostname;return url.protocol==='https:'&&!url.username&&!url.password&&(host.endsWith('.microlink.io')||host==='microlink-cdn.s3.amazonaws.com'||host==='urlscan.io')?url.href:null;}catch{return null;}}
  function previewHTML(item,large=false){
    const image=item.preview,host=new URL(item.url).hostname,url=safePreviewURL(image?.url);
    if(!image)return '<div class="preview-placeholder">Screenshots were not requested for this run.</div>';
    if(image.status==='pending')return '<div class="preview-placeholder"><span aria-hidden="true">◌</span> Requesting a page screenshot…<small>HTTP findings are already available.</small></div>';
    if(image.status!=='available'||!url)return `<div class="preview-placeholder">Screenshot unavailable<small>${escape(image.note||'The provider could not capture this page.')}</small></div>`;
    const date=image.captured_at?`Scanned ${new Date(image.captured_at).toLocaleString()}`:'Capture time not supplied · may be cached';
    return `<a href="${escape(url)}" target="_blank" rel="noopener noreferrer" class="preview-image-link ${large?'large':''}" aria-label="Open screenshot of ${escape(host)}"><img src="${escape(url)}" alt="${escape(host)} page screenshot" loading="lazy" referrerpolicy="no-referrer"></a><div class="preview-caption"><strong>${escape(image.source)}${image.kind==='archived'?' · archived scan':''}</strong><small>${escape(date)}</small><p>${escape(image.note)}</p></div>`;
  }
  function renderPreviews(){
    const show=cloud&&current?.provider==='live-http';$('#page-previews').hidden=!show;
    if(!show)return;
    $('#preview-grid').innerHTML=current.items.map(item=>`<article class="preview-card"><div class="preview-card-heading"><strong>${escape(new URL(item.url).hostname)}</strong><button type="button" data-preview-open="${escape(item.id)}">Inspect ↗</button></div>${previewHTML(item)}</article>`).join('');
  }
  function schedulePreviews(job){job.items.forEach(item=>{item.preview={status:'pending'};previewQueue.push({job,item});});drainPreviews();}
  function drainPreviews(){
    while(previewBusy<2&&previewQueue.length){
      const {job,item}=previewQueue.shift();previewBusy++;
      api('/preview',{method:'POST',body:JSON.stringify({url:item.url}),signal:AbortSignal.timeout(30000)}).then(image=>{item.preview=image;}).catch(()=>{item.preview={status:'unavailable',note:'The screenshot request could not finish. HTTP findings are unaffected.'};}).finally(()=>{
        previewBusy--;saveHistory();if(current.id===job.id)renderPreviews();
        if(openedResult?.jobId===job.id&&openedResult?.itemId===item.id&&$('#detail-dialog').open&&$('#evidence-screenshot'))$('#evidence-screenshot').innerHTML=previewHTML(item,true);
        drainPreviews();
      });
    }
  }
  $('#quick-form').addEventListener('submit',async event=>{event.preventDefault();$('#quick-error').hidden=true;const button=$('#quick-submit');button.disabled=true;try{const data=prepareInput($('#quick-urls').value);await submit(data.urls,'Website inspection',data.duplicates,data.original,'live',$('#quick-screenshot').checked);}catch(error){setText('#quick-error',error.message);$('#quick-error').hidden=false;}finally{button.disabled=false;}});
  const historyKey='urlscan.cloud-history.v1';
  function saveHistory(){try{localStorage.setItem(historyKey,JSON.stringify([...history.values()].filter(j=>j.id!=='sample-preview').slice(-10)));}catch{/* Export remains available if browser storage is full or disabled. */}}
  function configureCloud(){
    cloud=true;$('#quick-form').hidden=false;$('#dialog-screenshot-field').hidden=false;$('#run-live-test').hidden=false;labels.no_flags='No priority findings';setText('#mode-pill','Live HTTP inspection');setText('#new-batch','Check a URL');
    $('#demo-banner p').innerHTML='<strong>Real HTTP evidence. Clear next steps.</strong> Check a public URL, or run a labeled sample test. No API key needed.';
    setText('#run-sample','Run sample test →');setText('#history-description','Your last 10 inspections are saved on this device. The public service has no shared scan-history database.');
    setText('#input-note','One public HTTP(S) URL per line. Up to five per live run; sample tests can contain six.');
    setText('#form-mode','HTTP inspection · no JavaScript execution');$('#cloud-mode-field').hidden=false;
    $('#batch-name').value='Website inspection';$('#batch-urls').value='https://www.python.org/';setText('.sidebar-bottom small','Python · FastAPI · Vercel');setText('.app-footer b','2.1');
    setText('#workspace .metrics .metric:nth-child(2)>span','NO PRIORITY FINDINGS');setText('#workspace .metrics .metric:nth-child(2) small','Limited HTTP baseline checklist');
    setText('#workspace table th:nth-child(4)','REQUESTS / HOPS');setText('#workspace table th:nth-child(5)','LATENCY / REGION');
    setText('.workspace-footnote','Live checks inspect HTTP headers, redirects and bounded HTML only. They do not execute JavaScript or detect malware. Sample evidence is fictional.');
    setText('#view-architecture .page-heading p:not(.eyebrow)','A stateless Python endpoint collects bounded evidence and returns actionable, source-labeled results.');
    $('.architecture-flow').innerHTML='<span>Dashboard</span><b>→</b><span>FastAPI</span><b>→</b><span>Public-IP guard</span><b>→</b><span>Async HTTP</span><b>→</b><span>Evidence</span>';
    $('.engineering-grid').innerHTML='<article><span>01</span><h2>Real, bounded checks</h2><p>Inspect HTTP status, redirects, headers and page metadata. Five URLs per batch, two concurrent checks and a 24-second batch deadline.</p></article><article><span>02</span><h2>Connections with boundaries</h2><p>Resolve each hostname, reject internal or mixed DNS answers and connect to the validated public IP. Redirects are validated again.</p></article><article><span>03</span><h2>Evidence before labels</h2><p>Every finding includes a reason and recommendation. A missing header does not prove a vulnerability; a failed request never becomes a clean result.</p></article><article><span>04</span><h2>Built for Vercel</h2><p>Stateless Python Functions, no local database or daemon. History belongs to your browser; CSV and JSON exports retain result provenance.</p></article>';
    try{const saved=JSON.parse(localStorage.getItem(historyKey)||'[]');if(Array.isArray(saved))saved.slice(-10).forEach(job=>{if(typeof job.id==='string'&&typeof job.name==='string'&&typeof job.status==='string'&&Number.isFinite(job.created)&&Array.isArray(job.events)&&['demo','live-http'].includes(job.provider)&&Array.isArray(job.items)&&job.items.length<=6&&job.items.every(item=>{try{return ['http:','https:'].includes(new URL(item.url).protocol);}catch{return false;}})){if(active(job)){job.status='cancelled';job.items.forEach(i=>{if(['running','queued'].includes(i.status))i.status='cancelled';});}history.set(job.id,job);}});}catch{/* Ignore a corrupted browser history. */}
  }
  async function init(){
    try{
      samples=await (await fetch('samples.json')).json();fillSamples();current=snapshot();history.set(current.id,current);
      if(apiBase){config=await api('/config');if(config.mode==='cloud'){configureCloud();render();return;}setText('#mode-pill',config.synthetic?'Local API · demo provider':'Local API · urlscan.io');setText('#history-description','Investigation history is persisted in the local SQLite database.');if(!config.synthetic){$('#visibility-field').hidden=false;setText('#form-mode','Live provider · URLs leave this server');setText('#demo-banner p','Live provider enabled. Submitted URLs are sent to urlscan.io using your configured API key.');setText('#demo-banner button','Load sample URLs');$('#run-sample').hidden=true;}else{setText('#demo-banner p','The local Python backend is running. Sample scans use synthetic data and are persisted in SQLite.');}const jobs=(await api('/jobs')).jobs;if(jobs.length){current=await api(`/jobs/${jobs[0].id}`);history.set(current.id,current);if(active(current))poll(current.id);}}
      render();
    }catch(error){setText('#live-status','The workspace could not start.');toast(error.message);$('#run-sample').disabled=true;$('#new-batch').disabled=true;}
  }
  init();
})();
