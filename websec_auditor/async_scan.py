"""Asynchronous Background Scan Job Manager & Queue.

Grounded in:
  - CWE-400 / OWASP A04 / ASVS V13: Bounded concurrency pool, memory throttling, and job TTL.
  - CWE-200 / CWE-532: Zero sensitive credential leakage in job state summaries.
"""
from __future__ import annotations

import concurrent.futures
import html
import os
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from websec_auditor import config
from websec_auditor import netsafe
from websec_auditor import notifier
from websec_auditor import usage
from websec_auditor.scanner import engine
from websec_auditor.analyzer.analyze import analyze, summarize


_JOBS: Dict[str, Dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()
_EXECUTOR: Optional[concurrent.futures.ThreadPoolExecutor] = None


def get_executor() -> concurrent.futures.ThreadPoolExecutor:
    """Lazily initialize the bounded thread pool executor."""
    global _EXECUTOR
    if _EXECUTOR is None:
        _EXECUTOR = concurrent.futures.ThreadPoolExecutor(
            max_workers=config.MAX_ASYNC_WORKERS,
            thread_name_prefix="websec-async-worker"
        )
    return _EXECUTOR


def _prune_expired_jobs_locked() -> None:
    """Remove jobs that exceed the TTL (default 24h) to avoid memory leaks."""
    now = time.time()
    expired = [
        job_id for job_id, job in _JOBS.items()
        if (now - job.get("created_at", now)) > config.ASYNC_JOB_TTL_SECONDS
    ]
    for jid in expired:
        _JOBS.pop(jid, None)


def enqueue_scan_job(
    target: str,
    crawl: bool = False,
    custom_headers: Optional[Dict[str, str]] = None,
    webhook_url: Optional[str] = None,
    webhook_secret: Optional[str] = None,
    email: Optional[str] = None,
    report_base_url: str = "https://websec-audit.site",
    allow_private: bool = False
) -> Dict[str, Any]:
    """Enqueue a new scan job into the asynchronous worker queue."""
    job_id = str(uuid.uuid4())
    now = time.time()

    # Pre-validate webhook and email if provided (fail early)
    if webhook_url:
        netsafe.validate_target(webhook_url.strip(), allow_private=allow_private)
    if email and not notifier.is_valid_email(email.strip()):
        raise notifier.NotificationError(f"Invalid email recipient: {email!r}")

    job_record = {
        "id": job_id,
        "target": target,
        "crawl": crawl,
        "custom_headers": custom_headers or {},
        "status": "queued",  # queued -> running -> completed / failed
        "progress": 0,
        "created_at": now,
        "started_at": None,
        "completed_at": None,
        "error": None,
        "summary": None,
        "findings_count": 0,
        "webhook_url": webhook_url.strip() if webhook_url else None,
        "webhook_status": None,
        "email": email.strip() if email else None,
        "email_status": None,
        "report_url": f"{report_base_url.rstrip('/')}/scan/report?id={job_id}" if report_base_url else "",
    }

    with _JOBS_LOCK:
        _prune_expired_jobs_locked()
        _JOBS[job_id] = job_record

    # Submit background execution task
    executor = get_executor()
    executor.submit(
        _execute_scan_job,
        job_id,
        target,
        crawl,
        custom_headers or {},
        webhook_url,
        webhook_secret,
        email,
        allow_private
    )

    return get_sanitized_job(job_id)


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve raw job by ID."""
    with _JOBS_LOCK:
        return _JOBS.get(job_id)


def get_sanitized_job(job_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve job metadata safe for external display (no raw headers or secrets)."""
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return None
        return {
            "id": job["id"],
            "target": job["target"],
            "crawl": job["crawl"],
            "status": job["status"],
            "progress": job["progress"],
            "created_at": job["created_at"],
            "started_at": job["started_at"],
            "completed_at": job["completed_at"],
            "error": job["error"],
            "summary": job["summary"],
            "findings_count": job["findings_count"],
            "has_webhook": bool(job["webhook_url"]),
            "webhook_status": job["webhook_status"],
            "has_email": bool(job["email"]),
            "email_status": job["email_status"],
            "report_url": job["report_url"],
        }


def _execute_scan_job(
    job_id: str,
    target: str,
    crawl: bool,
    custom_headers: Dict[str, str],
    webhook_url: Optional[str],
    webhook_secret: Optional[str],
    email: Optional[str],
    allow_private: bool
) -> None:
    """Worker task that runs the scan, analyzer, and triggers alerts."""
    with _JOBS_LOCK:
        if job_id not in _JOBS:
            return
        _JOBS[job_id]["status"] = "running"
        _JOBS[job_id]["started_at"] = time.time()
        _JOBS[job_id]["progress"] = 25

    try:
        # Run scan safely within netsafe guard
        with netsafe.private_allowed(allow_private):
            if crawl:
                from websec_auditor.crawler import scan_site
                res = scan_site(target, custom_headers=custom_headers)
            else:
                res = engine.scan(target, custom_headers=custom_headers)

        with _JOBS_LOCK:
            _JOBS[job_id]["progress"] = 65

        # Enriched analysis
        en = analyze(res)
        summary = notifier.build_summary_stats(en)

        with _JOBS_LOCK:
            _JOBS[job_id]["progress"] = 85
            _JOBS[job_id]["summary"] = summary
            _JOBS[job_id]["findings_count"] = len(en)
            _JOBS[job_id]["_raw_findings"] = en

        try:
            usage.increment()
        except Exception:
            pass

        report_url = _JOBS[job_id].get("report_url", "")

        # 1. Trigger Webhook Dispatch
        if webhook_url:
            try:
                wb_res = notifier.send_webhook(
                    webhook_url=webhook_url,
                    target=target,
                    findings=en,
                    secret=webhook_secret,
                    report_url=report_url,
                    allow_private=allow_private
                )
                with _JOBS_LOCK:
                    _JOBS[job_id]["webhook_status"] = "delivered"
            except Exception as e:
                with _JOBS_LOCK:
                    _JOBS[job_id]["webhook_status"] = f"failed: {str(e)}"

        # 2. Trigger Email Alert Dispatch
        if email:
            try:
                em_res = notifier.send_email_alert(
                    recipient=email,
                    target=target,
                    findings=en,
                    report_url=report_url
                )
                with _JOBS_LOCK:
                    _JOBS[job_id]["email_status"] = em_res.get("status", "sent")
            except Exception as e:
                with _JOBS_LOCK:
                    _JOBS[job_id]["email_status"] = f"failed: {str(e)}"

        with _JOBS_LOCK:
            _JOBS[job_id]["status"] = "completed"
            _JOBS[job_id]["progress"] = 100
            _JOBS[job_id]["completed_at"] = time.time()

    except Exception as e:
        with _JOBS_LOCK:
            _JOBS[job_id]["status"] = "failed"
            _JOBS[job_id]["error"] = str(e)
            _JOBS[job_id]["completed_at"] = time.time()
