import asyncio
import hashlib
import hmac
import json
import logging
import os
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
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
GITVERSE_WEBHOOK_SECRET = os.getenv("GITVERSE_WEBHOOK_SECRET", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITVERSE_TOKEN = os.getenv("GITVERSE_TOKEN", "")
GITVERSE_API_BASE_URL = os.getenv("GITVERSE_API_BASE_URL", "https://gitverse.ru/api/v4").rstrip("/")

ALLOWED_GITHUB_EVENTS = {"push", "pull_request"}
ALLOWED_GITVERSE_EVENTS = {"push", "merge_request", "pull_request"}

app = FastAPI(title="Webhook Relay Service", version="1.0.0")
logger = logging.getLogger(__name__)


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
    return {
        "provider": "gitverse",
        "project_id": project_id,
        "pr_number": pr_number,
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

        comment_body = _build_comment_text(scan_id=scan_id, status=status, report=report)

        if pr_context.get("provider") == "github":
            await _post_github_comment(
                owner=str(pr_context.get("owner") or ""),
                repo=str(pr_context.get("repo") or ""),
                pr_number=int(pr_context["pr_number"]),
                body=comment_body,
            )
            return

        if pr_context.get("provider") == "gitverse":
            await _post_gitverse_comment(
                project_id=int(pr_context["project_id"]),
                pr_number=int(pr_context["pr_number"]),
                body=comment_body,
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
