"""Small durable SQLite queue. One connection per operation; all mutations are transactions."""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path


class Store:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.db() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, provider TEXT NOT NULL,
                visibility TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
                created REAL NOT NULL, updated REAL NOT NULL, duplicates INTEGER NOT NULL,
                use_cache INTEGER NOT NULL, request_key TEXT UNIQUE, fingerprint TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS items (
                id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id), url TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued', result TEXT, error TEXT,
                scan_id TEXT, cached INTEGER NOT NULL DEFAULT 0, updated REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS items_job ON items(job_id);
            CREATE INDEX IF NOT EXISTS items_url ON items(url, status, updated);
            CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL REFERENCES jobs(id),
                at REAL NOT NULL, message TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS events_job ON events(job_id,seq);
            """)

    @contextmanager
    def db(self):
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def event(self, job_id: str, message: str):
        with self.db() as db:
            db.execute("INSERT INTO events(job_id,at,message) VALUES(?,?,?)", (job_id,time.time(),message))

    def create(self, urls, name, provider, visibility, duplicates, use_cache, key=None):
        fingerprint = json.dumps([urls,name,provider,visibility,use_cache], separators=(",",":"))
        now, job_id = time.time(), uuid.uuid4().hex
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if key:
                existing = db.execute("SELECT id,fingerprint FROM jobs WHERE request_key=?", (key,)).fetchone()
                if existing:
                    if existing["fingerprint"] != fingerprint:
                        raise ValueError("Idempotency key was already used for a different request.")
                    return existing["id"], False
            # Bound the pending queue as well as individual batch sizes.
            count = db.execute("SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running')").fetchone()[0]
            if count >= 20:
                raise OverflowError("The queue is full. Wait for a batch to finish.")
            db.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?,?,?)", (job_id,name,provider,visibility,"queued",now,now,duplicates,int(use_cache),key,fingerprint))
            db.executemany("INSERT INTO items(id,job_id,url,updated) VALUES(?,?,?,?)", [(uuid.uuid4().hex,job_id,url,now) for url in urls])
            db.execute("INSERT INTO events(job_id,at,message) VALUES(?,?,?)", (job_id,now,f"Queued {len(urls)} unique URLs; removed {duplicates} duplicates."))
        return job_id, True

    def recover(self, provider=None):
        with self.db() as db:
            if provider:
                db.execute("UPDATE jobs SET status='queued',updated=? WHERE status='running' AND provider=?", (time.time(),provider))
                db.execute("UPDATE items SET status='queued' WHERE status='running' AND job_id IN (SELECT id FROM jobs WHERE provider=?)",(provider,))
            else:
                db.execute("UPDATE jobs SET status='queued',updated=? WHERE status='running'", (time.time(),))
                db.execute("UPDATE items SET status='queued' WHERE status='running'")

    def next_job(self, provider=None, job_id=None):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM jobs WHERE status='queued' AND (? IS NULL OR provider=?) AND (? IS NULL OR id=?) ORDER BY created LIMIT 1",(provider,provider,job_id,job_id)).fetchone()
            if row:
                db.execute("UPDATE jobs SET status='running',updated=? WHERE id=?", (time.time(),row["id"]))
            return dict(row) if row else None

    def items(self, job_id):
        with self.db() as db:
            return [dict(row) for row in db.execute("SELECT * FROM items WHERE job_id=? ORDER BY rowid",(job_id,))]

    def item_update(self, item_id, **fields):
        allowed = {"status","result","error","scan_id","cached"}
        if not fields or not fields.keys() <= allowed:
            raise ValueError("Invalid item fields")
        fields["updated"] = time.time()
        with self.db() as db:
            # A cancellation that wins the transaction cannot be overwritten by a late result.
            db.execute(f"UPDATE items SET {','.join(f'{key}=?' for key in fields)} WHERE id=? AND status!='cancelled'", (*fields.values(),item_id))

    def is_cancelled(self, job_id):
        with self.db() as db:
            row = db.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
            return row is None or row["status"] == "cancelled"

    def finish(self, job_id):
        with self.db() as db:
            failed = db.execute("SELECT COUNT(*) FROM items WHERE job_id=? AND status='failed'",(job_id,)).fetchone()[0]
            db.execute("UPDATE jobs SET status=?,updated=? WHERE id=? AND status!='cancelled'", ("completed_with_errors" if failed else "completed",time.time(),job_id))

    def cancel(self, job_id):
        with self.db() as db:
            row = db.execute("SELECT status FROM jobs WHERE id=?",(job_id,)).fetchone()
            if not row:
                return False
            if row["status"] in {"queued","running"}:
                db.execute("UPDATE jobs SET status='cancelled',updated=? WHERE id=?",(time.time(),job_id))
                db.execute("UPDATE items SET status='cancelled',updated=? WHERE job_id=? AND status IN ('queued','running')",(time.time(),job_id))
            return True

    def cached(self, url, provider, visibility, ttl):
        with self.db() as db:
            row = db.execute("""SELECT i.result FROM items i JOIN jobs j ON j.id=i.job_id
                WHERE i.url=? AND j.provider=? AND j.visibility=? AND i.status='completed' AND i.updated>?
                AND i.cached=0 ORDER BY i.updated DESC LIMIT 1""",(url,provider,visibility,time.time()-ttl)).fetchone()
            return json.loads(row[0]) if row else None

    def retry(self, job_id):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status FROM jobs WHERE id=?",(job_id,)).fetchone()
            if not row:
                return None
            if row["status"] != "completed_with_errors":
                return False
            if db.execute("SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running')").fetchone()[0] >= 20:
                raise OverflowError("The queue is full. Wait for a batch to finish.")
            db.execute("UPDATE items SET status='queued',error=NULL,updated=? WHERE job_id=? AND status='failed'",(time.time(),job_id))
            db.execute("UPDATE jobs SET status='queued',updated=? WHERE id=?",(time.time(),job_id))
            return True

    def job(self, job_id):
        with self.db() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=?",(job_id,)).fetchone()
            if not row:
                return None
            job = dict(row)
            job.pop("fingerprint");job.pop("request_key")
            job["items"] = [dict(item) for item in db.execute("SELECT * FROM items WHERE job_id=? ORDER BY rowid",(job_id,))]
            for item in job["items"]:
                item["result"] = json.loads(item["result"]) if item["result"] else None
            job["events"] = [dict(event) for event in db.execute("SELECT at,message,seq FROM events WHERE job_id=? ORDER BY seq DESC LIMIT 100",(job_id,))][::-1]
            job["total"] = len(job["items"])
            job["done"] = sum(item["status"] in {"completed","failed","cancelled"} for item in job["items"])
            return job

    def history(self):
        with self.db() as db:
            return [dict(row) for row in db.execute("""SELECT j.id,j.name,j.provider,j.status,j.created,
                COUNT(i.id) total, SUM(i.status IN ('completed','failed','cancelled')) done
                FROM jobs j LEFT JOIN items i ON i.job_id=j.id GROUP BY j.id ORDER BY j.created DESC LIMIT 50""")]
