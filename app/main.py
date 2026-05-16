import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
from urllib.parse import urlparse
from typing import Any

import httpx
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request

load_dotenv()

BACKEND_BASE_URL = os.getenv("BACKEND_BASE_URL", "https://backend-findwork.ru.tuna.am").rstrip("/")
BACKEND_API_KEY = os.getenv("BACKEND_API_KEY", "")
DEFAULT_SCAN_QUERY = os.getenv("DEFAULT_SCAN_QUERY", "")
SCAN_INTERACTIVE = os.getenv("SCAN_INTERACTIVE", "false").lower() == "true"
REPORT_POLL_INTERVAL_SECONDS = max(2, int(os.getenv("REPORT_POLL_INTERVAL_SECONDS", "10")))
REPORT_WAIT_TIMEOUT_SECONDS = max(30, int(os.getenv("REPORT_WAIT_TIMEOUT_SECONDS", "1800")))
REPORT_COMMENT_MAX_CHARS = max(1000, int(os.getenv("REPORT_COMMENT_MAX_CHARS", "12000")))
INLINE_COMMENTS_MAX = max(1, int(os.getenv("INLINE_COMMENTS_MAX", "20")))
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
GITVERSE_WEBHOOK_SECRET = os.getenv("GITVERSE_WEBHOOK_SECRET", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITVERSE_TOKEN = os.getenv("GITVERSE_TOKEN", "")
GITVERSE_API_BASE_URL = os.getenv("GITVERSE_API_BASE_URL", "https://gitverse.ru/api/v4").rstrip("/")

ALLOWED_GITHUB_EVENTS = {"push", "pull_request"}
ALLOWED_GITVERSE_EVENTS = {"push", "merge_request", "pull_request"}

app = FastAPI(title="Webhook Relay Service", version="1.0.0")
logger = logging.getLogger(__name__)
FILE_LINE_PATTERN = re.compile(
    r"(?:Файл|File)\s*:\s*(?P<path>[^:\n]+):(?P<line>\d+)",
    flags=re.IGNORECASE,
)


def _verify_signature(
    *,
    body: bytes,
    provided_signature: str | None,
    secret: str,
    missing_message: str,
    invalid_message: str,
) -> None:
    if not secret:
        return

    if not provided_signature:
        raise HTTPException(status_code=401, detail=missing_message)

    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, provided_signature):
        raise HTTPException(status_code=401, detail=invalid_message)


def _extract_repo_url(payload: dict[str, Any]) -> str:
    candidates = [
        ((payload.get("repository") or {}).get("clone_url")),
        ((payload.get("repository") or {}).get("git_http_url")),
        ((payload.get("repository") or {}).get("http_url")),
        ((payload.get("repository") or {}).get("url")),
        ((payload.get("project") or {}).get("git_http_url")),
        ((payload.get("project") or {}).get("http_url")),
        ((payload.get("project") or {}).get("url")),
        ((payload.get("repo") or {}).get("clone_url")),
        ((payload.get("repo") or {}).get("url")),
        payload.get("clone_url"),
        payload.get("repo_url"),
        payload.get("repository_url"),
    ]
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.startswith(("http://", "https://")):
            return candidate
    raise HTTPException(status_code=400, detail="Repository URL is missing in webhook payload")


def _extract_event(provider: str, header_event: str | None, payload: dict[str, Any]) -> str:
    if provider == "github":
        event = header_event or ""
    else:
        event = header_event or payload.get("event_name") or payload.get("object_kind") or ""
    return str(event).strip().lower()


def _backend_headers() -> dict[str, str]:
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if BACKEND_API_KEY:
        headers["Authorization"] = f"Bearer {BACKEND_API_KEY}"
    return headers


def _extract_owner_repo_from_url(repo_url: str) -> tuple[str, str]:
    parsed = urlparse(repo_url)
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        return "", ""
    owner = parts[-2]
    repo = parts[-1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return owner, repo


def _extract_pr_context(provider: str, event: str, payload: dict[str, Any], repo_url: str) -> dict[str, Any] | None:
    if provider == "github":
        if event != "pull_request":
            return None
        repo = payload.get("repository") or {}
        owner = (repo.get("owner") or {}).get("login") or ""
        repo_name = repo.get("name") or ""
        if not owner or not repo_name:
            owner, repo_name = _extract_owner_repo_from_url(repo_url)
        pr_number = (payload.get("pull_request") or {}).get("number")
        if not isinstance(pr_number, int):
            return None
        return {
            "provider": "github",
            "owner": owner,
            "repo": repo_name,
            "pr_number": pr_number,
            "head_sha": ((payload.get("pull_request") or {}).get("head") or {}).get("sha") or "",
        }

    if event not in {"pull_request", "merge_request"}:
        return None
    object_attributes = payload.get("object_attributes") or {}
    pr_number = object_attributes.get("iid") or object_attributes.get("number")
    if not isinstance(pr_number, int):
        pr_number = (payload.get("pull_request") or {}).get("number")
    project = payload.get("project") or {}
    project_id = project.get("id")
    if not isinstance(project_id, int):
        project_id = (payload.get("repository") or {}).get("id")
    if not isinstance(pr_number, int) or not isinstance(project_id, int):
        return None
    diff_refs = object_attributes.get("diff_refs") or {}
    last_commit = object_attributes.get("last_commit")
    last_commit_sha = ""
    if isinstance(last_commit, dict):
        last_commit_sha = str(last_commit.get("id") or "")
    elif isinstance(last_commit, str):
        last_commit_sha = last_commit
    return {
        "provider": "gitverse",
        "project_id": project_id,
        "pr_number": pr_number,
        "base_sha": diff_refs.get("base_sha") or object_attributes.get("oldrev") or "",
        "start_sha": diff_refs.get("start_sha") or object_attributes.get("oldrev") or "",
        "head_sha": diff_refs.get("head_sha") or last_commit_sha or object_attributes.get("newrev") or "",
    }


def _build_comment_text(scan_id: str, status: str, report: str | None) -> str:
    status_label = status.upper()
    summary = [
        "## Automated Security Scan",
        f"- Scan ID: `{scan_id}`",
        f"- Status: `{status_label}`",
    ]
    details = report or "Report is empty."
    if len(details) > REPORT_COMMENT_MAX_CHARS:
        details = details[:REPORT_COMMENT_MAX_CHARS] + "\n\n...truncated..."
    return "\n".join(summary) + "\n\n### Findings\n\n" + details


def _extract_report_findings(report: str | None) -> list[dict[str, Any]]:
    if not report:
        return []
    lines = report.splitlines()
    findings: list[dict[str, Any]] = []
    idx = 0
    while idx < len(lines):
        match = FILE_LINE_PATTERN.search(lines[idx])
        if not match:
            idx += 1
            continue
        path = match.group("path").strip().lstrip("./")
        line = int(match.group("line"))
        details: list[str] = []
        cursor = idx + 1
        while cursor < len(lines):
            next_match = FILE_LINE_PATTERN.search(lines[cursor])
            if next_match:
                break
            cleaned = lines[cursor].strip()
            if cleaned:
                details.append(cleaned)
            cursor += 1
        findings.append(
            {
                "path": path,
                "line": line,
                "location_raw": f"Файл: {path}:{line}",
                "details": "\n".join(details[:12]),
            }
        )
        idx = cursor

    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for finding in findings:
        key = (str(finding["path"]), int(finding["line"]))
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
        if len(unique) >= INLINE_COMMENTS_MAX:
            break
    return unique


def _build_inline_comment_text(scan_id: str, finding: dict[str, Any]) -> str:
    details = str(finding.get("details") or "Potential security issue found by automated scan.")
    if len(details) > 1200:
        details = details[:1200] + "\n\n...truncated..."
    location_text = str(finding.get("location_raw") or f"Файл: {finding['path']}:{finding['line']}")
    return (
        "Automated security finding.\n\n"
        f"Scan ID: `{scan_id}`\n"
        f"{location_text}\n\n"
        f"{details}"
    )


def _build_inline_failures_comment(scan_id: str, failures: list[str]) -> str:
    preview = "\n".join(failures[:10])
    if len(failures) > 10:
        preview += f"\n... and {len(failures) - 10} more"
    return (
        "## Automated Security Scan\n"
        f"- Scan ID: `{scan_id}`\n\n"
        "Inline comments were not created for some findings:\n\n"
        f"{preview}"
    )


async def _post_github_comment(*, owner: str, repo: str, pr_number: int, body: str) -> None:
    if not GITHUB_TOKEN:
        return
    if not owner or not repo:
        return
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=headers, json={"body": body})
    if response.status_code >= 400:
        raise RuntimeError(f"GitHub comment failed: {response.status_code} {response.text}")


async def _get_github_pr_head_sha(*, owner: str, repo: str, pr_number: int) -> str:
    if not GITHUB_TOKEN or not owner or not repo:
        return ""
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, headers=headers)
    if response.status_code >= 400:
        logger.warning("Failed to fetch PR head SHA: %s", response.text)
        return ""
    body = response.json()
    return str(((body.get("head") or {}).get("sha")) or "")


async def _post_github_inline_comment(
    *,
    owner: str,
    repo: str,
    pr_number: int,
    head_sha: str,
    path: str,
    line: int,
    body: str,
) -> tuple[bool, str]:
    if not GITHUB_TOKEN or not owner or not repo or not head_sha:
        return False, "missing GitHub token/repo/head_sha"
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    payload = {
        "body": body,
        "commit_id": head_sha,
        "path": path,
        "line": line,
        "side": "RIGHT",
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=headers, json=payload)
    if response.status_code >= 400:
        logger.warning("GitHub inline comment rejected for %s:%s: %s", path, line, response.text)
        return False, response.text
    return True, ""


async def _post_github_file_thread_comment(
    *,
    owner: str,
    repo: str,
    pr_number: int,
    head_sha: str,
    path: str,
    body: str,
) -> tuple[bool, str]:
    if not GITHUB_TOKEN or not owner or not repo or not head_sha:
        return False, "missing GitHub token/repo/head_sha"
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    payload = {
        "body": body,
        "commit_id": head_sha,
        "path": path,
        "subject_type": "file",
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=headers, json=payload)
    if response.status_code >= 400:
        logger.warning("GitHub file thread rejected for %s: %s", path, response.text)
        return False, response.text
    return True, ""


async def _post_gitverse_comment(*, project_id: int, pr_number: int, body: str) -> None:
    if not GITVERSE_TOKEN:
        return
    url = f"{GITVERSE_API_BASE_URL}/projects/{project_id}/merge_requests/{pr_number}/notes"
    headers = {
        "Authorization": f"Bearer {GITVERSE_TOKEN}",
        "PRIVATE-TOKEN": GITVERSE_TOKEN,
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=headers, json={"body": body})
    if response.status_code >= 400:
        raise RuntimeError(f"GitVerse comment failed: {response.status_code} {response.text}")


async def _post_gitverse_inline_comment(
    *,
    project_id: int,
    pr_number: int,
    path: str,
    line: int,
    body: str,
    base_sha: str,
    start_sha: str,
    head_sha: str,
) -> tuple[bool, str]:
    if not GITVERSE_TOKEN or not base_sha or not start_sha or not head_sha:
        return False, "missing GitVerse token or diff refs"
    url = f"{GITVERSE_API_BASE_URL}/projects/{project_id}/merge_requests/{pr_number}/discussions"
    headers = {
        "Authorization": f"Bearer {GITVERSE_TOKEN}",
        "PRIVATE-TOKEN": GITVERSE_TOKEN,
        "Content-Type": "application/json",
    }
    payload = {
        "body": body,
        "position": {
            "position_type": "text",
            "base_sha": base_sha,
            "start_sha": start_sha,
            "head_sha": head_sha,
            "new_path": path,
            "new_line": line,
        },
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=headers, json=payload)
    if response.status_code >= 400:
        logger.warning("GitVerse inline comment rejected for %s:%s: %s", path, line, response.text)
        return False, response.text
    return True, ""


async def _wait_scan_and_comment(scan_id: str, pr_context: dict[str, Any]) -> None:
    try:
        waited = 0
        status = "running"
        report: str | None = None
        headers = _backend_headers()
        url = f"{BACKEND_BASE_URL}/scan/{scan_id}/report"

        async with httpx.AsyncClient(timeout=30.0) as client:
            while waited <= REPORT_WAIT_TIMEOUT_SECONDS:
                response = await client.get(url, headers=headers)
                if response.status_code >= 400:
                    status = "failed"
                    report = f"Backend report request failed ({response.status_code}): {response.text}"
                    break

                response_body = response.json()
                status = str(response_body.get("status") or "running")
                report = response_body.get("report")
                if status in {"completed", "failed"}:
                    break

                waited += REPORT_POLL_INTERVAL_SECONDS
                await asyncio.sleep(REPORT_POLL_INTERVAL_SECONDS)

        if status not in {"completed", "failed"}:
            status = "timeout"
            report = "Timed out while waiting for backend scan result."

        if pr_context.get("provider") == "github":
            findings = _extract_report_findings(report) if status == "completed" else []
            posted_inline = 0
            posted_file_threads = 0
            failed_inline: list[str] = []
            owner = str(pr_context.get("owner") or "")
            repo = str(pr_context.get("repo") or "")
            pr_number = int(pr_context["pr_number"])
            fresh_head_sha = await _get_github_pr_head_sha(owner=owner, repo=repo, pr_number=pr_number)
            head_sha = fresh_head_sha or str(pr_context.get("head_sha") or "")
            for finding in findings:
                ok, reason = await _post_github_inline_comment(
                    owner=owner,
                    repo=repo,
                    pr_number=pr_number,
                    head_sha=head_sha,
                    path=str(finding["path"]),
                    line=int(finding["line"]),
                    body=_build_inline_comment_text(scan_id, finding),
                )
                if ok:
                    posted_inline += 1
                else:
                    thread_body = (
                        _build_inline_comment_text(scan_id, finding)
                        + "\n\n_Inline line attachment failed, posted as file thread._"
                    )
                    file_ok, file_reason = await _post_github_file_thread_comment(
                        owner=owner,
                        repo=repo,
                        pr_number=pr_number,
                        head_sha=head_sha,
                        path=str(finding["path"]),
                        body=thread_body,
                    )
                    if file_ok:
                        posted_file_threads += 1
                    else:
                        failed_inline.append(
                            f"- {finding.get('location_raw')}: inline={reason[:100] if reason else 'rejected'}, file={file_reason[:100] if file_reason else 'rejected'}"
                        )
            if posted_inline == 0 and posted_file_threads == 0:
                await _post_github_comment(
                    owner=owner,
                    repo=repo,
                    pr_number=pr_number,
                    body=_build_comment_text(scan_id=scan_id, status=status, report=report),
                )
            elif failed_inline:
                await _post_github_comment(
                    owner=owner,
                    repo=repo,
                    pr_number=pr_number,
                    body=_build_inline_failures_comment(scan_id, failed_inline),
                )
            return

        if pr_context.get("provider") == "gitverse":
            findings = _extract_report_findings(report) if status == "completed" else []
            posted_inline = 0
            failed_inline: list[str] = []
            for finding in findings:
                ok, reason = await _post_gitverse_inline_comment(
                    project_id=int(pr_context["project_id"]),
                    pr_number=int(pr_context["pr_number"]),
                    path=str(finding["path"]),
                    line=int(finding["line"]),
                    body=_build_inline_comment_text(scan_id, finding),
                    base_sha=str(pr_context.get("base_sha") or ""),
                    start_sha=str(pr_context.get("start_sha") or ""),
                    head_sha=str(pr_context.get("head_sha") or ""),
                )
                if ok:
                    posted_inline += 1
                else:
                    failed_inline.append(
                        f"- {finding.get('location_raw')}: {reason[:180] if reason else 'rejected by API'}"
                    )
            if posted_inline == 0:
                await _post_gitverse_comment(
                    project_id=int(pr_context["project_id"]),
                    pr_number=int(pr_context["pr_number"]),
                    body=_build_comment_text(scan_id=scan_id, status=status, report=report),
                )
            elif failed_inline:
                await _post_gitverse_comment(
                    project_id=int(pr_context["project_id"]),
                    pr_number=int(pr_context["pr_number"]),
                    body=_build_inline_failures_comment(scan_id, failed_inline),
                )
            return
    except Exception:
        logger.exception("Failed to publish scan comment for scan_id=%s", scan_id)


async def _forward_to_backend(*, repo_url: str, provider: str, event: str, delivery: str | None) -> dict[str, Any]:
    payload: dict[str, Any] = {"repo_url": repo_url, "interactive": SCAN_INTERACTIVE}
    if DEFAULT_SCAN_QUERY:
        payload["query"] = DEFAULT_SCAN_QUERY
    # else:
    #     payload["query"] = f"Webhook-triggered security scan ({provider}:{event})"
    url = f"{BACKEND_BASE_URL}/scan/start"
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=_backend_headers(), json=payload)

    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail={
                "message": "Backend /scan/start rejected webhook relay",
                "status_code": response.status_code,
                "response": response.text,
            },
        )

    body: dict[str, Any] = response.json()
    return {
        "ok": True,
        "provider": provider,
        "event": event,
        "delivery": delivery,
        "repo_url": repo_url,
        "backend_scan_id": body.get("scan_id"),
    }


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/webhooks/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_event: str | None = Header(default=None),
    x_github_delivery: str | None = Header(default=None),
    x_hub_signature_256: str | None = Header(default=None),
) -> dict[str, Any]:
    body = await request.body()
    _verify_signature(
        body=body,
        provided_signature=x_hub_signature_256,
        secret=GITHUB_WEBHOOK_SECRET,
        missing_message="Missing X-Hub-Signature-256 header",
        invalid_message="Invalid GitHub webhook signature",
    )

    try:
        payload = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc

    event = _extract_event("github", x_github_event, payload)
    if event == "ping":
        return {"ok": True, "provider": "github", "event": "ping", "delivery": x_github_delivery}
    if event not in ALLOWED_GITHUB_EVENTS:
        return {
            "ok": True,
            "provider": "github",
            "event": event,
            "delivery": x_github_delivery,
            "ignored": True,
            "reason": f"Allowed events: {sorted(ALLOWED_GITHUB_EVENTS)}",
        }

    repo_url = _extract_repo_url(payload)
    backend_response = await _forward_to_backend(
        repo_url=repo_url,
        provider="github",
        event=event,
        delivery=x_github_delivery,
    )
    pr_context = _extract_pr_context("github", event, payload, repo_url)
    if pr_context and backend_response.get("backend_scan_id"):
        background_tasks.add_task(_wait_scan_and_comment, str(backend_response["backend_scan_id"]), pr_context)
    backend_response["comment_scheduled"] = bool(pr_context and backend_response.get("backend_scan_id"))
    return backend_response


@app.post("/webhooks/gitverse")
async def gitverse_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_gitverse_event: str | None = Header(default=None),
    x_gitverse_delivery: str | None = Header(default=None),
    x_gitverse_signature_256: str | None = Header(default=None),
    x_hub_signature_256: str | None = Header(default=None),
) -> dict[str, Any]:
    body = await request.body()
    signature = x_gitverse_signature_256 or x_hub_signature_256
    _verify_signature(
        body=body,
        provided_signature=signature,
        secret=GITVERSE_WEBHOOK_SECRET,
        missing_message="Missing GitVerse signature header",
        invalid_message="Invalid GitVerse webhook signature",
    )

    try:
        payload = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc

    event = _extract_event("gitverse", x_gitverse_event, payload)
    if event not in ALLOWED_GITVERSE_EVENTS:
        return {
            "ok": True,
            "provider": "gitverse",
            "event": event,
            "delivery": x_gitverse_delivery,
            "ignored": True,
            "reason": f"Allowed events: {sorted(ALLOWED_GITVERSE_EVENTS)}",
        }

    repo_url = _extract_repo_url(payload)
    backend_response = await _forward_to_backend(
        repo_url=repo_url,
        provider="gitverse",
        event=event,
        delivery=x_gitverse_delivery,
    )
    pr_context = _extract_pr_context("gitverse", event, payload, repo_url)
    if pr_context and backend_response.get("backend_scan_id"):
        background_tasks.add_task(_wait_scan_and_comment, str(backend_response["backend_scan_id"]), pr_context)
    backend_response["comment_scheduled"] = bool(pr_context and backend_response.get("backend_scan_id"))
    return backend_response
