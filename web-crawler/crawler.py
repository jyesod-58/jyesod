"""
웹 크롤러: Playwright로 페이지를 수집하고 LangChain 문서로 정리합니다.

기본 모드(--llm none)는 API 키 없이 동작하며, 결과를 Claude Pro 채팅에
올려 분석할 수 있는 for_claude.md 파일로 만들어 줍니다.

사용 예:
  python crawler.py https://example.com
  python crawler.py -f urls.txt --scroll 3
  python crawler.py https://example.com --depth 2 --max-pages 50   # 하위 페이지까지
  python crawler.py -f urls.txt --llm claude --fields "제목,가격,날짜"
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlparse, urlunparse, urljoin, quote, quote_plus
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.robotparser import RobotFileParser
from xml.sax.saxutils import escape as xml_escape

from dotenv import load_dotenv
from langchain_core.documents import Document
from playwright.async_api import TimeoutError as PWTimeout
from playwright.async_api import async_playwright

try:
    import trafilatura
except ImportError:  # 없으면 본문 텍스트 전체를 사용
    trafilatura = None

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0 Safari/537.36"
)

# 진행 상황 출력 훅. 웹 UI 등에서 교체하면 로그를 가로챌 수 있다(기본은 print).
LOG_CALLBACK = None
# 진행도 훅: PROGRESS_CALLBACK(done, total, percent). 웹 UI가 진행률 막대를 그릴 때 쓴다.
PROGRESS_CALLBACK = None


def log(msg: str) -> None:
    (LOG_CALLBACK or print)(msg)


# ---------------------------------------------------------------- robots.txt
_robots_cache: dict[str, RobotFileParser] = {}


def _load_robots(base: str) -> RobotFileParser:
    rp = RobotFileParser()
    try:
        req = Request(base + "/robots.txt", headers={"User-Agent": USER_AGENT})
        class SameHostRedirect(HTTPRedirectHandler):
            def redirect_request(self, request, fp, code, msg, headers, newurl):
                if urlparse(newurl).hostname != urlparse(base).hostname:
                    raise ValueError("범위 밖 robots.txt 리다이렉트 차단")
                return super().redirect_request(request, fp, code, msg, headers, newurl)
        with build_opener(SameHostRedirect()).open(req, timeout=10) as r:
            rp.parse(r.read().decode("utf-8", "ignore").splitlines())
    except HTTPError as e:
        if e.code in (401, 403):
            rp.disallow_all = True
        else:
            rp.allow_all = True
    except Exception:
        rp.allow_all = True  # robots.txt를 읽지 못하면 허용으로 간주
    return rp


async def allowed_by_robots(url: str) -> bool:
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        return True
    base = f"{p.scheme}://{p.netloc}"
    if base not in _robots_cache:
        _robots_cache[base] = await asyncio.to_thread(_load_robots, base)
    return _robots_cache[base].can_fetch("*", url)


# ---------------------------------------------------------------- 텍스트 정리
def clean_text(text: str) -> str:
    text = re.sub(r"[ \t]+", " ", text)
    text = "\n".join(line.strip() for line in text.splitlines())
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def html_to_markdown(html: str, url: str, fallback_text: str) -> str:
    """광고·메뉴를 걷어낸 본문을 마크다운으로. 실패하면 화면 텍스트 전체."""
    if trafilatura is not None:
        md = trafilatura.extract(
            html,
            url=url,
            output_format="markdown",
            include_tables=True,
            include_links=False,
            favor_recall=True,
        )
        if md and len(md.strip()) >= 200:
            return md.strip()
    return clean_text(fallback_text)


# ---------------------------------------------------------------- 링크 추적
# 페이지가 아닌 자원(이미지·스크립트·압축 등)은 하위 링크로 따라가지 않음
ASSET_EXT = {
    "css", "js", "mjs", "json", "xml", "rss", "png", "jpg", "jpeg", "gif", "webp",
    "svg", "ico", "bmp", "woff", "woff2", "ttf", "otf", "eot", "mp4", "webm",
    "mp3", "wav", "avi", "mov", "zip", "gz", "tar", "rar", "7z", "exe", "dmg",
}


def _same_site(link_host: str, parent_host: str, allow_sub: bool) -> bool:
    """승인한 정확한 호스트 또는 그 아래의 서브도메인만 허용한다."""
    link_host = link_host.lower().rstrip(".")
    parent_host = parent_host.lower().rstrip(".")
    if link_host == parent_host:
        return True
    return bool(allow_sub and parent_host and link_host.endswith("." + parent_host))


def _in_scope(url: str, approved_hosts: set[str], allow_sub: bool = False) -> bool:
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and not p.username and not p.password and any(
            _same_site(p.hostname or "", host, allow_sub) for host in approved_hosts
        )
    except ValueError:
        return False


def _clean_link(href: str) -> str | None:
    """링크를 정규화(프래그먼트 제거)하고, http/https가 아니면 버림."""
    try:
        u = urlparse(href)
    except Exception:
        return None
    if u.scheme not in ("http", "https") or not u.netloc:
        return None
    return urlunparse((u.scheme, u.netloc, u.path or "/", u.params, u.query, ""))


# ---------------------------------------------------------------- 원문 캡처
# Burp "Save selected items"와 같은 형태(요청/응답 원문)를 만들기 위해,
# 페이지가 주고받는 문서·XHR·fetch 응답을 가로채 raw HTTP 텍스트로 재구성한다.
CAPTURE_TYPES = {"document", "xhr", "fetch"}
_STATUS_TEXT = {
    200: "OK", 201: "Created", 204: "No Content", 301: "Moved Permanently",
    302: "Found", 303: "See Other", 304: "Not Modified", 307: "Temporary Redirect",
    308: "Permanent Redirect", 400: "Bad Request", 401: "Unauthorized",
    403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
    500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
}


def _redact(text: str, secrets: list[str]) -> str:
    """캡처한 원문에서 비밀번호 등 민감한 입력값을 가린다."""
    for s in secrets:
        if s:
            variants = {s, quote(s, safe=""), quote_plus(s), json.dumps(s)[1:-1], json.dumps(s, ensure_ascii=False)[1:-1]}
            variants |= {re.sub(r"%[0-9A-Fa-f]{2}", lambda match: match[0].lower(), v) for v in variants}
            for value in sorted(variants, key=len, reverse=True):
                text = text.replace(value, "***REDACTED***")
    return text


def _redact_bytes(body: bytes, secrets: list[str], charset: str = "utf-8") -> bytes:
    """원래 바이트와 문자셋을 보존하면서 알려진 비밀번호 바이트만 치환한다."""
    for secret in secrets:
        if not secret:
            continue
        variants = {secret, quote(secret, safe=""), quote_plus(secret), json.dumps(secret)[1:-1]}
        variants |= {re.sub(r"%[0-9A-Fa-f]{2}", lambda match: match[0].lower(), v) for v in variants}
        for variant in sorted(variants, key=len, reverse=True):
            for encoding in {charset, "utf-8"}:
                try:
                    encoded = variant.encode(encoding)
                except (LookupError, UnicodeError):
                    continue
                if encoded:
                    body = body.replace(encoded, b"***REDACTED***")
    return body


_SECRET_HEADERS = {"cookie", "set-cookie", "authorization", "proxy-authorization", "x-api-key", "x-auth-token"}


def _raw_request(req, secrets: list[str], redact_headers: bool = True) -> bytes:
    """Playwright 요청 -> raw HTTP 요청 텍스트."""
    p = urlparse(req.url)
    target = p.path or "/"
    if p.query:
        target += "?" + p.query
    lines = [f"{req.method} {target} HTTP/1.1"]
    headers = req.headers
    if "host" not in headers:
        lines.append(f"Host: {p.netloc}")
    for k, v in headers.items():
        if k.lower() != "content-length":
            lines.append(f"{k}: {'***REDACTED***' if redact_headers and k.lower() in _SECRET_HEADERS else v}")
    body = req.post_data_buffer or b""
    ctype = headers.get("content-type", "")
    charset = re.search(r'charset=["\']?([^;\s"\']+)', ctype, re.I)
    body = _redact_bytes(body, secrets, charset.group(1) if charset else "utf-8")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    return _redact("\r\n".join(lines), secrets).encode("utf-8", "replace") + b"\r\n\r\n" + body


async def _raw_response(resp, secrets: list[str], redact_headers: bool = True) -> bytes | None:
    """Playwright 응답 -> raw HTTP 응답 텍스트(상태줄 + 헤더 + 본문)."""
    try:
        body = await resp.body()
    except Exception:
        return None  # 리다이렉트 등 본문을 못 가져오는 경우
    reason = _STATUS_TEXT.get(resp.status, "")
    head = f"HTTP/1.1 {resp.status} {reason}".rstrip() + "\r\n"
    try:
        headers = await resp.all_headers()
    except Exception:
        headers = resp.headers
    for k, v in headers.items():
        if k.lower() in ("content-encoding", "transfer-encoding", "content-length"):
            continue  # body()는 이미 압축이 풀린 상태
        head += f"{k}: {'***REDACTED***' if redact_headers and k.lower() in _SECRET_HEADERS else v}\r\n"
    charset = re.search(r'charset=["\']?([^;\s"\']+)', headers.get("content-type", ""), re.I)
    body = _redact_bytes(body, secrets, charset.group(1) if charset else "utf-8")
    head += f"Content-Length: {len(body)}\r\n"
    head_bytes = _redact(head, secrets).encode("utf-8", "replace") + b"\r\n"
    return head_bytes + body


# ---------------------------------------------------------------- 수집
async def fetch_page(context, url: str, args, collect_links: bool, secrets: list[str]) -> dict:
    page = await context.new_page()
    timeout_ms = args.timeout * 1000
    captured: list = []  # 이 페이지가 받은 응답 객체들

    def on_response(resp):
        try:
            if resp.request.resource_type in CAPTURE_TYPES and _in_scope(resp.url, args.approved_hosts, args.allow_subdomains):
                captured.append(resp)
        except Exception:
            pass

    if args.capture:
        page.on("response", on_response)

    try:
        response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        try:
            await page.wait_for_load_state("networkidle", timeout=10_000)
        except PWTimeout:
            pass  # 계속 통신하는 사이트는 그냥 진행
        if args.wait_for:
            await page.wait_for_selector(args.wait_for, timeout=timeout_ms)
        for _ in range(args.scroll):  # 무한 스크롤 페이지용
            await page.mouse.wheel(0, 4000)
            await page.wait_for_timeout(1000)

        html = await page.content()
        title = (await page.title()).strip()
        body_text = await page.inner_text("body")
        content = html_to_markdown(html, url, body_text)

        links: list[str] = []
        if collect_links:  # 하위 페이지 추적용. 브라우저가 절대경로로 변환해 줌
            try:
                links = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
            except Exception:
                links = []

        exchanges = []  # Burp 형식으로 저장할 요청/응답 쌍
        if args.capture:
            for resp in captured:
                raw_resp = await _raw_response(resp, secrets, not args.keep_secrets)
                if raw_resp is None:
                    continue
                try:
                    req = resp.request
                    exchanges.append({
                        "url": _redact(resp.url, secrets),
                        "method": req.method,
                        "status": resp.status,
                        "mime": (resp.headers.get("content-type", "") or "").split(";")[0],
                        "request_b64": base64.b64encode(_raw_request(req, secrets, not args.keep_secrets)).decode("ascii"),
                        "response_b64": base64.b64encode(raw_resp).decode("ascii"),
                    })
                except Exception:
                    pass

        doc = Document(
            page_content=content,
            metadata={
                "url": _redact(url, secrets),
                "title": title,
                "status": response.status if response else None,
                "fetched_at": datetime.now().isoformat(timespec="seconds"),
            },
        )
        return {"ok": True, "doc": doc, "links": links, "exchanges": exchanges}
    except Exception as e:
        return {"ok": False, "url": url, "error": f"{type(e).__name__}: {e}".splitlines()[0]}
    finally:
        await page.close()


# ---------------------------------------------------------------- 로그인
# 로그인 폼에서 흔히 쓰이는 입력란 이름들. 선택자를 주지 않으면 이 순서로 찾는다.
_USER_SELECTORS = [
    "input[type=email]", "input[name*=user i]", "input[name*=login i]",
    "input[name*=email i]", "input[name*=id i]", "input[id*=user i]",
    "input[id*=login i]", "input[id*=email i]",
]
_PASS_SELECTORS = ["input[type=password]", "input[name*=pass i]", "input[id*=pass i]"]
_SUBMIT_SELECTORS = [
    "button[type=submit]", "input[type=submit]",
    "button:has-text('로그인')", "button:has-text('Login')",
    "button:has-text('Sign in')", "a:has-text('로그인')",
]


async def _first_visible(page, selectors: list[str]):
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            if await loc.count() and await loc.is_visible():
                return loc
        except Exception:
            continue
    return None


async def do_login(context, args) -> bool:
    """자동 또는 수동 로그인 후 세션(쿠키 등)을 컨텍스트에 남긴다."""
    page = await context.new_page()
    try:
        target = args.login_url or (args.urls[0] if args.urls else None)
        if not target:
            log("로그인할 주소가 없습니다. --login-url 을 지정하세요.")
            return False
        await page.goto(target, wait_until="domcontentloaded", timeout=args.timeout * 1000)
        try:
            await page.wait_for_load_state("networkidle", timeout=8000)
        except PWTimeout:
            pass

        if args.manual_login:
            # CLI는 터미널 Enter, 웹 UI는 manual_event(스레드 이벤트)로 이어받는다.
            manual_event = getattr(args, "manual_event", None)
            if manual_event is not None:
                log("수동 로그인: 열린 브라우저 창에서 로그인한 뒤, 웹 화면의 '로그인 완료' 버튼을 누르세요.")
                await asyncio.get_event_loop().run_in_executor(None, manual_event.wait)
            else:
                log("\n=== 수동 로그인 ===")
                log("열린 브라우저 창에서 직접 로그인한 뒤, 이 터미널에서 Enter를 누르세요.")
                log("(캡차·OTP·SSO 등 자동 입력이 어려운 경우에 사용)")
                await asyncio.get_event_loop().run_in_executor(None, input, "로그인 완료 후 Enter > ")
        else:
            user_box = await _first_visible(page, [args.username_selector] if args.username_selector else _USER_SELECTORS)
            pass_box = await _first_visible(page, [args.password_selector] if args.password_selector else _PASS_SELECTORS)
            if not user_box or not pass_box:
                log("로그인 입력란을 찾지 못했습니다. --username-selector / --password-selector 로 지정하거나 --manual-login 을 쓰세요.")
                return False
            await user_box.fill(args.username)
            await pass_box.fill(args.password)
            submit = await _first_visible(page, [args.submit_selector] if args.submit_selector else _SUBMIT_SELECTORS)
            if submit:
                await submit.click()
            else:
                await pass_box.press("Enter")
            try:
                await page.wait_for_load_state("networkidle", timeout=12_000)
            except PWTimeout:
                pass

        # 세션 유효성 간단 확인: 로그인 폼이 그대로면 실패로 간주
        still_form = await _first_visible(page, _PASS_SELECTORS)
        if still_form and not args.manual_login:
            log("로그인이 안 된 것 같습니다(비밀번호 입력란이 그대로 보임). 자격 증명이나 선택자를 확인하세요.")
            return False

        if args.session:
            await context.storage_state(path=args.session)
            log(f"세션 저장: {args.session}")
        log("로그인 완료.\n")
        return True
    except Exception as e:
        log(f"로그인 중 오류: {type(e).__name__}: {e}")
        return False
    finally:
        await page.close()


def _is_logout(url: str, pattern: str) -> bool:
    return bool(pattern) and re.search(pattern, url, re.I) is not None


async def crawl(urls: list[str], args) -> list[dict]:
    sem = asyncio.Semaphore(args.concurrency)
    follow = args.depth > 0
    secrets = [args.password] if (args.password and not args.keep_secrets) else []
    approved_urls = urls + ([args.login_url] if args.login_url else [])
    args.approved_hosts = {urlparse(u).hostname.lower().rstrip(".") for u in approved_urls if urlparse(u).hostname}
    if not args.approved_hosts or any(not _in_scope(u, args.approved_hosts, False) for u in approved_urls):
        raise ValueError("시작/로그인 주소는 승인한 호스트의 http(s) URL이어야 합니다.")

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=not args.show)
        ctx_kwargs = dict(
            user_agent=USER_AGENT,
            locale="ko-KR",
            viewport={"width": 1366, "height": 900},
            service_workers="block",
        )
        # 이전에 저장한 세션이 있으면 재사용(로그인 생략)
        if args.session and os.path.exists(args.session) and not (args.username or args.manual_login):
            ctx_kwargs["storage_state"] = args.session
            log(f"저장된 세션 사용: {args.session}")
        context = await browser.new_context(**ctx_kwargs)

        async def scoped_route(route):
            target = route.request.url
            if not _in_scope(target, args.approved_hosts, args.allow_subdomains):
                log(f"범위 밖 요청 차단: {target}")
                await route.abort("blockedbyclient")
                return
            try:
                # 브라우저에 리다이렉트를 맡기지 않고 모든 이동 대상의 범위를 확인한다.
                response = await route.fetch(url=target, max_redirects=0)
                location = response.headers.get("location")
                if response.status not in (301, 302, 303, 307, 308) or not location:
                    await route.fulfill(response=response)
                    return
                next_url = urljoin(target, location)
                if not _in_scope(next_url, args.approved_hosts, args.allow_subdomains):
                    log(f"범위 밖 리다이렉트 차단: {next_url}")
                else:
                    # 안전하게 fail closed: 자동 추적 대신 최종 URL의 명시적 입력을 요구한다.
                    log(f"리다이렉트 차단: 최종 승인 URL을 직접 입력하세요: {next_url}")
                await route.abort("blockedbyclient")
            except Exception as exc:
                log(f"범위 검사 요청 실패: {type(exc).__name__}")
                await route.abort("failed")

        await context.route("**/*", scoped_route)

        need_login = args.manual_login or (args.username and args.password)
        if need_login and "storage_state" not in ctx_kwargs:
            if not await do_login(context, args):
                await browser.close()
                return [{"ok": False, "url": urls[0] if urls else "", "error": "로그인 실패"}]

        visited: set[str] = set()
        frontier: list[str] = []
        for u in urls:
            if u not in visited:
                visited.add(u)
                frontier.append(u)

        cancel = getattr(args, "cancel_event", None)

        results: list[dict] = []
        depth = 0
        # ---- 진행도: 완료한 페이지 ÷ (지금까지 발견한 수집 예정 페이지, 최대 페이지가 상한) ----
        # 하위 링크는 수집하면서 발견되므로 분모가 늘 수 있다. 값이 되돌아가지 않게 단조 증가로 보정한다.
        state = {"done": 0, "level": 0, "pct": 0}

        def progress_now() -> tuple[int, int, int]:
            total = max(1, min(args.max_pages, len(results) + state["level"] + len(frontier)))
            done = min(state["done"], total)
            pct = min(99, int(done * 100 / total))  # 100%는 모두 끝난 뒤에만 표시
            state["pct"] = max(state["pct"], pct)
            return done, total, state["pct"]

        def report(msg: str = "") -> None:
            done, total, pct = progress_now()
            if PROGRESS_CALLBACK:
                PROGRESS_CALLBACK(done, total, pct)
            if msg:
                log(f"[{done}/{total} · {pct}%] {msg}")

        def enqueue(res: dict) -> None:
            """수집한 페이지의 링크를 발견 즉시 다음 단계 대기열에 넣는다."""
            for href in res.get("links", []):
                link = _clean_link(href)
                if not link or link in visited:
                    continue
                if not _in_scope(link, args.approved_hosts, args.allow_subdomains):
                    continue
                ext = os.path.splitext(urlparse(link).path)[1].lower().lstrip(".")
                if ext in ASSET_EXT:
                    continue
                if _is_logout(link, args.logout_pattern):
                    continue  # 세션이 풀리지 않도록 로그아웃 링크는 따라가지 않음
                visited.add(link)
                frontier.append(link)

        state["level"] = len(frontier)
        report()  # 0% 시작 알림

        while frontier and len(results) < args.max_pages:
            if cancel is not None and cancel.is_set():
                log("사용자 요청으로 수집을 중지합니다. 지금까지 수집한 내용을 저장합니다.")
                break
            level = frontier[: args.max_pages - len(results)]  # 남은 상한만큼만
            frontier = []
            state["level"] = len(level)
            collect = follow and depth < args.depth

            async def worker(url: str) -> dict:
                async with sem:
                    if cancel is not None and cancel.is_set():
                        return {"ok": False, "url": url, "error": "수집 중지됨"}
                    if _is_logout(url, args.logout_pattern):
                        state["done"] += 1
                        report(f"[깊이 {depth}] 건너뜀 (로그아웃 URL): {url}")
                        return {"ok": False, "url": url, "error": "로그아웃 URL이라 건너뜀"}
                    if not args.ignore_robots and not await allowed_by_robots(url):
                        state["done"] += 1
                        report(f"[깊이 {depth}] 건너뜀 (robots.txt 금지): {url}")
                        return {"ok": False, "url": url, "error": "robots.txt에서 수집을 금지함"}
                    res = await fetch_page(context, url, args, collect, secrets)
                    state["done"] += 1
                    if res["ok"]:
                        if collect:
                            enqueue(res)  # 분모(발견한 페이지 수)를 먼저 갱신한 뒤 진행도 계산
                        d = res["doc"]
                        report(f"[깊이 {depth}] 완료 ({len(d.page_content):,}자): {d.metadata['title'] or url}")
                    else:
                        report(f"[깊이 {depth}] 실패: {url} - {res['error']}")
                    await asyncio.sleep(args.delay)  # 서버 부담을 줄이기 위한 간격
                    return res

            level_results = await asyncio.gather(*(worker(u) for u in level))
            # 중지로 건너뛴 항목은 실패로 집계하지 않는다
            results.extend(r for r in level_results if r.get("error") != "수집 중지됨")

            if cancel is not None and cancel.is_set():
                break  # 중지 요청 시 다음 단계로 넘어가지 않음

            depth += 1

        stopped = cancel is not None and cancel.is_set()
        if not stopped:
            state["pct"] = 100
            if PROGRESS_CALLBACK:
                PROGRESS_CALLBACK(len(results), max(1, len(results)), 100)
        await browser.close()
    return results


# ---------------------------------------------------------------- 저장
def slugify(url: str) -> str:
    p = urlparse(url)
    s = re.sub(r"[^0-9A-Za-z가-힣]+", "_", f"{p.netloc}{p.path}").strip("_")
    return (s or "page")[:60]


CLAUDE_HEADER = """# 웹 수집 데이터

아래는 {count}개 웹 페이지에서 수집한 본문입니다. (수집 시각: {time})

분석 요청 예시 (이 파일을 Claude에 올린 뒤 아래처럼 물어보세요):
- 각 페이지의 핵심 내용을 3줄로 요약하고 공통점과 차이점을 정리해줘
- 페이지에 나온 상품/항목을 이름, 가격, 특징 열로 표로 만들어줘
- 이 데이터에서 눈에 띄는 트렌드나 이상한 점을 찾아줘

"""


def save_outputs(results: list[dict], args) -> Path:
    out_dir = Path(args.out) / datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    pages_dir = out_dir / "pages"
    pages_dir.mkdir(parents=True, exist_ok=True)

    records = []
    sections = []
    ok_results = [r for r in results if r["ok"]]

    for i, r in enumerate(results, 1):
        if not r["ok"]:
            records.append({"url": r["url"], "ok": False, "error": r["error"]})
            continue
        doc: Document = r["doc"]
        meta = doc.metadata
        record = {**meta, "ok": True, "length": len(doc.page_content), "content": doc.page_content}
        if "extracted" in r:
            record["extracted"] = r["extracted"]
        records.append(record)

        header = (
            f"# {meta['title'] or meta['url']}\n\n"
            f"- URL: {meta['url']}\n- 수집 시각: {meta['fetched_at']}\n\n"
        )
        (pages_dir / f"{i:02d}_{slugify(meta['url'])}.md").write_text(
            header + doc.page_content, encoding="utf-8"
        )

        body = doc.page_content
        if len(body) > args.max_chars:
            body = body[: args.max_chars] + f"\n\n...(이하 생략, 전체 {len(doc.page_content):,}자)"
        section = f"---\n\n## [{i}] {meta['title'] or meta['url']}\n\nURL: {meta['url']}\n\n"
        if r.get("extracted"):
            section += "### LLM 추출 결과\n\n```json\n"
            section += json.dumps(r["extracted"], ensure_ascii=False, indent=2) + "\n```\n\n### 본문\n\n"
        sections.append(section + body + "\n")

    (out_dir / "results.json").write_text(
        json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    claude_md = CLAUDE_HEADER.format(
        count=len(ok_results), time=datetime.now().strftime("%Y-%m-%d %H:%M")
    ) + "\n".join(sections)
    (out_dir / "for_claude.md").write_text(claude_md, encoding="utf-8")

    # --- "Burp 사이트맵 트리" 아티팩트에 바로 넣을 수 있는 형식 ---
    url_lines, xml_items = [], []
    for r in results:
        if r["ok"]:
            u = r["doc"].metadata["url"]
            st = r["doc"].metadata.get("status")
        else:
            u, st = r["url"], None
        url_lines.append(u)
        safe = u.replace("]]>", "]]]]><![CDATA[>")  # CDATA 분리로 원래 URL 보존
        status_tag = f"\n    <status>{st}</status>" if st else ""
        xml_items.append(f"  <item>\n    <url><![CDATA[{safe}]]></url>{status_tag}\n  </item>")
    (out_dir / "sitemap_urls.txt").write_text("\n".join(url_lines) + "\n", encoding="utf-8")
    (out_dir / "sitemap.xml").write_text(
        '<?xml version="1.0"?>\n<items>\n' + "\n".join(xml_items) + "\n</items>\n",
        encoding="utf-8",
    )

    # --- Burp "Save selected items" 형식: 요청·응답 원문 포함 ---
    # 민감정보 탐지기와 Burp 사이트맵 트리 아티팩트에 그대로 올릴 수 있다.
    burp_items = []
    for r in results:
        if not r.get("ok"):
            continue
        for ex in r.get("exchanges", []):
            safe_url = ex["url"].replace("]]>", "]]]]><![CDATA[>")
            burp_items.append(
                "  <item>\n"
                f"    <url><![CDATA[{safe_url}]]></url>\n"
                f"    <method>{xml_escape(ex['method'])}</method>\n"
                f"    <status>{ex['status']}</status>\n"
                f"    <mimetype>{xml_escape(ex['mime'])}</mimetype>\n"
                f'    <request base64="true">{ex["request_b64"]}</request>\n'
                f'    <response base64="true">{ex["response_b64"]}</response>\n'
                "  </item>"
            )
    if burp_items:
        (out_dir / "burp_history.xml").write_text(
            '<?xml version="1.0"?>\n<items>\n' + "\n".join(burp_items) + "\n</items>\n",
            encoding="utf-8",
        )
    return out_dir, len(burp_items)


# ---------------------------------------------------------------- 실행
def read_urls(args) -> list[str]:
    urls = list(args.urls)
    if args.file:
        for line in Path(args.file).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    seen, unique = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            unique.append(u)
    return unique


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Playwright + LangChain 웹 크롤러")
    p.add_argument("urls", nargs="*", help="수집할 URL (여러 개 가능)")
    p.add_argument("-f", "--file", help="URL 목록 파일 (한 줄에 하나, #은 주석)")
    p.add_argument("-o", "--out", default="output", help="결과 폴더 (기본: output)")

    g = p.add_argument_group("수집 옵션")
    g.add_argument("--scroll", type=int, default=0, help="아래로 스크롤할 횟수 (무한 스크롤 페이지)")
    g.add_argument("--wait-for", help="이 CSS 선택자가 나타날 때까지 대기")
    g.add_argument("--timeout", type=int, default=30, help="페이지당 제한 시간(초)")
    g.add_argument("--concurrency", type=int, default=2, help="동시에 여는 페이지 수")
    g.add_argument("--delay", type=float, default=1.0, help="요청 사이 대기(초)")
    g.add_argument("--show", action="store_true", help="브라우저 창을 띄워서 실행")
    g.add_argument("--ignore-robots", action="store_true", help="robots.txt 무시 (권장하지 않음)")

    g = p.add_argument_group("원문 캡처 옵션 (Burp 형식)")
    g.add_argument("--capture", dest="capture", action="store_true", default=True,
                   help="요청·응답 원문을 burp_history.xml로 저장 (기본 켜짐)")
    g.add_argument("--no-capture", dest="capture", action="store_false",
                   help="원문 캡처 끄기 (화면 본문만 수집)")

    g = p.add_argument_group("로그인 옵션 (권한이 있는 대상에만 사용)")
    g.add_argument("--login-url", help="로그인 페이지 주소 (미지정 시 첫 URL 사용)")
    g.add_argument("--username", help="로그인 ID")
    g.add_argument("--password", help="로그인 비밀번호 (캡처 원문에서는 자동으로 가림)")
    g.add_argument("--username-selector", help="ID 입력란 CSS 선택자 (자동 탐지가 실패할 때)")
    g.add_argument("--password-selector", help="비밀번호 입력란 CSS 선택자")
    g.add_argument("--submit-selector", help="로그인 버튼 CSS 선택자")
    g.add_argument("--manual-login", action="store_true",
                   help="브라우저 창에서 직접 로그인(캡차·OTP·SSO용). --show 가 함께 켜짐")
    g.add_argument("--session", help="세션 저장/재사용 파일 (예: session.json). 다음 실행 때 로그인 생략")
    g.add_argument("--logout-pattern", default=r"logout|signout|sign-out|logoff|/exit",
                   help="수집·추적에서 제외할 로그아웃 URL 패턴(정규식)")
    g.add_argument("--keep-secrets", action="store_true",
                   help="캡처 원문에서 비밀번호를 가리지 않음 (권장하지 않음)")

    g = p.add_argument_group("하위 페이지 추적 옵션")
    g.add_argument("--depth", type=int, default=0,
                   help="링크를 따라갈 단계 (0=시작 주소만, 1=직접 링크, 2=두 단계…)")
    g.add_argument("--max-pages", type=int, default=50, help="전체 수집 상한 (기본: 50)")
    g.add_argument("--allow-subdomains", action="store_true",
                   help="입력한 승인 호스트 아래의 서브도메인만 추가 허용")

    g = p.add_argument_group("LLM 추출 옵션 (선택, 별도 비용 발생 가능)")
    g.add_argument("--llm", choices=["none", "claude", "ollama"], default="none",
                   help="none: 수집만 (기본) / claude: Claude API / ollama: 로컬 LLM")
    g.add_argument("--model", help="사용할 모델 이름 (미지정 시 .env 또는 기본값)")
    g.add_argument("--fields", help='뽑아낼 항목, 쉼표로 구분 (예: "제목,가격,날짜")')
    g.add_argument("--instruction", help="추출 지시문 (예: 채용 공고의 회사명과 연봉만)")
    g.add_argument("--max-chunks", type=int, default=5, help="페이지당 LLM에 보낼 최대 조각 수")

    g = p.add_argument_group("출력 옵션")
    g.add_argument("--max-chars", type=int, default=20000,
                   help="for_claude.md에 넣을 페이지당 최대 글자 수")
    return p


def main() -> None:
    load_dotenv()
    args = build_parser().parse_args()
    if args.llm != "none":
        raise SystemExit("LLM 추출은 이 배포본에 포함되지 않습니다. --llm none을 사용하세요.")
    if args.manual_login:
        args.show = True  # 직접 로그인하려면 창이 보여야 함
    urls = read_urls(args)
    if not urls:
        build_parser().print_help()
        sys.exit("\nURL을 입력하거나 -f urls.txt 로 목록 파일을 지정하세요.")

    if args.depth > 0:
        print(f"시작 주소 {len(urls)}개 · 깊이 {args.depth} · 최대 {args.max_pages}페이지 수집 시작\n")
    else:
        print(f"{len(urls)}개 페이지 수집 시작 (하위 페이지는 --depth 로 추적)\n")
    results = asyncio.run(crawl(urls, args))

    if args.llm != "none":
        from extractor import Extractor  # LLM을 쓸 때만 불러옴

        fields = [f.strip() for f in args.fields.split(",")] if args.fields else []
        extractor = Extractor(args.llm, args.model, fields, args.instruction, args.max_chunks)
        ok = [r for r in results if r["ok"]]
        print(f"\nLLM({args.llm})으로 {len(ok)}개 페이지 분석 중")
        for n, r in enumerate(ok, 1):
            r["extracted"] = extractor.extract(r["doc"])
            print(f"  [{n}/{len(ok)}] {r['doc'].metadata['title'] or r['doc'].metadata['url']}")

    out_dir, burp_count = save_outputs(results, args)
    ok_count = sum(r["ok"] for r in results)
    print(f"\n완료: 성공 {ok_count} / 실패 {len(results) - ok_count}")
    print(f"결과 폴더: {out_dir.resolve()}")
    print(f"Claude에 올릴 파일: {(out_dir / 'for_claude.md').resolve()}")
    print(f"Burp 사이트맵 트리에 넣을 파일: {(out_dir / 'sitemap.xml').resolve()}")
    if burp_count:
        print(f"요청·응답 원문({burp_count}건): {(out_dir / 'burp_history.xml').resolve()}")
        print("  -> 민감정보 탐지기 / Burp 사이트맵 트리 아티팩트에 올리세요.")


if __name__ == "__main__":
    main()
