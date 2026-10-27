"""Single-job Playwright entrypoint. Input/output contain sanitized metadata only."""

import asyncio
import importlib.util
import json
import re
import sys
import time
from urllib.parse import urlsplit

from playwright.async_api import async_playwright

_policy_spec = importlib.util.spec_from_file_location("sandbox_network_policy", "/opt/scamshield/network_policy.py")
if _policy_spec is None or _policy_spec.loader is None:
    raise RuntimeError("sandbox policy unavailable")
_policy = importlib.util.module_from_spec(_policy_spec)
_policy_spec.loader.exec_module(_policy)
is_public_address = _policy.is_public_address
parse_ip_literal = _policy.parse_ip_literal


PROXY = "http://egress-proxy:8080"
MAX_REQUESTS = 120


def origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        if parsed.scheme not in ("http", "https") or not host:
            return "[non-http origin]"
        address = parse_ip_literal(host)
        if address is not None:
            normalized = f"[{address.compressed}]" if address.version == 6 else address.compressed
        else:
            normalized = host.rstrip(".").encode("idna").decode("ascii").lower()
        return f"{parsed.scheme.lower()}://{normalized}"
    except (ValueError, UnicodeError):
        return "[invalid origin]"


def validate_request_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https") or not host or parsed.username is not None or parsed.password is not None:
        return False
    if port not in (None, 80 if parsed.scheme == "http" else 443):
        return False
    address = parse_ip_literal(host)
    if address is not None:
        return is_public_address(address)
    try:
        name = host.rstrip(".").encode("idna").decode("ascii").lower()
        return "." in name and not name.endswith((".localhost", ".local", ".internal", ".test", ".invalid", ".example"))
    except (UnicodeError, ValueError):
        return False


async def analyze(target: str) -> dict:
    if not validate_request_url(target):
        raise ValueError("invalid target")
    initial_origin = origin(target)
    started = time.monotonic()
    requests: dict[int, dict] = {}
    console_errors = 0
    download_attempts = 0
    final_status = None
    content_type = None
    navigation_error = None

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            proxy={"server": PROXY, "bypass": "<-loopback>"},
            args=[
                "--disable-quic", "--disable-background-networking", "--no-first-run",
                "--disable-sync", "--disable-default-apps", "--proxy-bypass-list=<-loopback>",
                "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE egress-proxy",
            ],
        )
        try:
            context = await browser.new_context(ignore_https_errors=True, accept_downloads=False)
            page = await context.new_page()
            page.set_default_navigation_timeout(30000)
            page.set_default_timeout(5000)

            async def guard(route):
                if validate_request_url(route.request.url):
                    await route.continue_()
                else:
                    await route.abort("blockedbyclient")

            await page.route("**/*", guard)

            def record_request(request):
                if len(requests) >= MAX_REQUESTS:
                    return
                try:
                    frame_origin = origin(request.frame.url)
                except Exception:
                    frame_origin = "[unavailable]"
                requests[id(request)] = {
                    "origin": origin(request.url),
                    "resource_type": request.resource_type[:24],
                    "frame_origin": frame_origin,
                    "status": None,
                }

            def record_response(response):
                entry = requests.get(id(response.request))
                if entry is None:
                    return
                entry["status"] = response.status

            def record_console(message):
                nonlocal console_errors
                if message.type == "error":
                    console_errors += 1

            def record_download(_download):
                nonlocal download_attempts
                download_attempts += 1

            page.on("request", record_request)
            page.on("response", record_response)
            page.on("console", record_console)
            page.on("download", record_download)

            response = None
            try:
                response = await page.goto(target, wait_until="domcontentloaded")
            except Exception as exc:
                # Exception messages can contain the untrusted URL, so only the type is kept.
                navigation_error = type(exc).__name__[:80]
            if response is not None:
                final_status = response.status
                candidate = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                content_type = candidate if re.fullmatch(r"[a-z0-9!#$&^_.+-]{1,64}/[a-z0-9!#$&^_.+-]{1,64}", candidate) else None

            redirects = []
            if response is not None:
                request = response.request
                while request is not None and len(redirects) < 20:
                    redirects.append(origin(request.url))
                    request = request.redirected_from
                redirects.reverse()

            forms = []
            try:
                raw_forms = await page.locator("form").evaluate_all(
                    "forms => forms.slice(0, 50).map(form => ({method: (form.method || 'get').toLowerCase(), action: form.action, password_fields: [...form.elements].filter(el => el.type === 'password').length, field_count: form.elements.length}))"
                )
                for form in raw_forms:
                    forms.append({
                        "method": form["method"] if form["method"] in ("get", "post", "dialog") else "other",
                        "action_origin": origin(form["action"]),
                        "password_fields": min(int(form["password_fields"]), 50),
                        "field_count": min(int(form["field_count"]), 100),
                    })
            except Exception:
                forms = []

            try:
                frames = sorted({origin(frame.url) for frame in page.frames if frame.url and frame != page.main_frame})[:50]
            except Exception:
                frames = []

            nav_ms = max(0, int((time.monotonic() - started) * 1000))
            observations = {
                "initial_origin": initial_origin,
                "final_origin": origin(response.url) if response is not None else None,
                "redirect_chain": redirects,
                "navigation": {
                    "http_status": final_status,
                    "content_type": content_type,
                    "duration_ms": nav_ms,
                    "error_type": navigation_error,
                },
                "requests": list(requests.values()),
                "console_error_count": console_errors,
                "frames": frames,
                "forms": forms,
                "download_attempt_count": download_attempts,
                "screenshot": {"available": False, "reason": "Screenshots are omitted to avoid retaining arbitrary page content."},
            }
            await context.close()
            return observations
        finally:
            await browser.close()


async def main() -> None:
    try:
        if sys.argv[1:] != ["--stdin"]:
            raise ValueError("unsupported worker invocation")
        target = json.loads(sys.stdin.readline())["url"]
        evidence = await analyze(target)
        result = evidence
    except Exception as exc:
        # Exception messages can contain target URL or page-controlled text.
        result = {"worker_error": type(exc).__name__[:80]}
    sys.stdout.write(json.dumps(result, separators=(",", ":")))
    sys.stdout.flush()


if __name__ == "__main__":
    asyncio.run(main())
