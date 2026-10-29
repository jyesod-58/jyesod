"""
웹 크롤러 로컬 UI (추가 설치 불필요, 파이썬 표준 라이브러리만 사용).

실행:
    python webapp.py            # http://127.0.0.1:8777 열림
    python webapp.py --port 9000 --open   # 포트 지정 + 브라우저 자동 열기

브라우저에서 URL·옵션·로그인 정보를 넣고 [수집 시작]을 누르면,
crawler.py 가 그대로 실행되어 요청·응답 원문(burp_history.xml) 등을 만들고
화면에서 바로 내려받을 수 있습니다. 모든 처리는 이 PC 안에서만 이뤄집니다.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import mimetypes
import os
import re
import secrets
import shutil
import threading
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

HERE = Path(__file__).resolve().parent
UI_FILE = HERE / "web_ui.html"
DETECTOR_FILE = HERE / "pii_finder.html"
API_TOKEN = secrets.token_hex(32)
MAX_BODY_BYTES = 1024 * 1024
DOWNLOAD_NAMES = {"burp_history.xml", "for_claude.md", "sitemap.xml", "sitemap_urls.txt", "results.json"}

# 필요한 파일이 한 폴더에 모여 있는지 먼저 확인(다른 폴더에서 실행하는 실수 방지)
_missing = [n for n in ("crawler.py", "web_ui.html", "pii_finder.html") if not (HERE / n).exists()]
if _missing:
    raise SystemExit(
        "\n[오류] 같은 폴더에 필요한 파일이 없습니다: " + ", ".join(_missing)
        + f"\n현재 webapp.py 위치: {HERE}"
        + "\n→ crawler.py, webapp.py, web_ui.html, pii_finder.html 을 한 폴더(예: web-crawler)에 모은 뒤,"
        + "\n  그 폴더에서 python webapp.py --open 을 실행하세요."
    )

def _get_crawler():
    """HTML/Burp 분석 화면은 추가 패키지 없이 제공하고 수집할 때만 로드한다."""
    try:
        import crawler  # 같은 폴더의 crawler.py; Python 모듈 캐시로 재사용
        return crawler
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError(
            f"크롤러 의존성이 없습니다 ({exc.name or '알 수 없는 패키지'}). "
            "web-crawler 폴더에서 python -m pip install -r requirements.txt 실행 후 "
            "python -m playwright install chromium 을 실행하세요. "
            "Burp XML 직접 분석 화면은 설치 없이 사용할 수 있습니다."
        ) from exc

# 민감정보 탐지기(iframe)에 수집 결과를 자동으로 밀어 넣기 위한 수신 스크립트.
# 탐지기 IIFE 내부(load 함수 범위)에 끼워 넣는다.
_DETECTOR_HOOK = (
    "setLoaded(false);\n"
    "window.addEventListener('message',function(ev){"
    "if(!ev||!ev.data||ev.source!==window.parent||ev.origin!==window.location.origin)return;"
    "try{"
    "if(ev.data.type==='load-burp'){Promise.resolve(load(ev.data.text,ev.data.name||'burp_history.xml',false)).catch(e=>console.error(e));}"
    "else if(ev.data.type==='clear-data'){goHome();}"
    "}catch(e){console.error(e);}});"
)


def _detector_html() -> bytes:
    html = DETECTOR_FILE.read_text(encoding="utf-8")
    if "type==='load-burp'" not in html:
        # 탐지기 안에 setLoaded(false); 가 여러 번 나올 수 있으므로(예: 홈 버튼 함수 안),
        # 스크립트 끝의 초기화 호출(마지막 위치)에만 연동 코드를 붙인다.
        head, sep, tail = html.rpartition("setLoaded(false);")
        if sep:
            html = head + _DETECTOR_HOOK + tail
    return html.encode("utf-8")

OUTPUT_DIR = HERE / "output"
_RUN_DIR = re.compile(r"^\d{8}_\d{6}(?:_\d{6})?$")  # 기존/새 결과 폴더 이름


def _dir_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += (Path(root) / f).stat().st_size
            except OSError:
                pass
    return total


def _list_outputs() -> dict:
    """output/ 아래의 수집 결과 폴더(날짜_시간)와 저장된 로그인 세션(*.json)만 센다."""
    runs, sessions = [], []
    if OUTPUT_DIR.is_dir():
        for p in sorted(OUTPUT_DIR.iterdir()):
            if p.is_symlink():
                continue
            if p.is_dir() and _RUN_DIR.match(p.name):
                runs.append(p)
            elif p.is_file() and p.suffix.lower() == ".json":
                sessions.append(p)
    return {
        "runs": runs,
        "sessions": sessions,
        "bytes": sum(_dir_size(p) for p in runs),
    }


def _clear_outputs(include_sessions: bool) -> dict:
    """결과 폴더(output/YYYYMMDD_HHMMSS)만 삭제한다. 그 밖의 파일·폴더는 건드리지 않는다."""
    info = _list_outputs()
    removed_runs = removed_sessions = 0
    freed = info["bytes"]
    for p in info["runs"]:
        # 심볼릭 링크를 따라 밖으로 나가지 않도록 실제 경로가 output/ 안인지 한 번 더 확인
        if p.resolve().parent != OUTPUT_DIR.resolve():
            continue
        shutil.rmtree(p, ignore_errors=True)
        removed_runs += 1
    if include_sessions:
        for p in info["sessions"]:
            if p.resolve().parent != OUTPUT_DIR.resolve():
                continue
            try:
                p.unlink()
                removed_sessions += 1
            except OSError:
                pass
    return {"removed_runs": removed_runs, "removed_sessions": removed_sessions, "freed_bytes": freed}


# 한 번에 하나의 작업만 실행(로컬 단일 사용자용)
JOB: dict = {"state": "idle"}
JOB_LOCK = threading.Lock()


def _new_job() -> dict:
    return {
        "state": "running",      # running | waiting_login | done | error
        "log": [],               # 진행 로그 줄
        "files": [],             # [{name, size}]
        "out_dir": None,
        "error": None,
        "started": datetime.now().strftime("%H:%M:%S"),
        "needs_manual": False,
        "manual_event": None,
        "cancel_event": None,
        "progress": {"done": 0, "total": 0, "pct": 0},
        "phase": "ready",        # login | crawl | save | done
        "stopped": False,
    }


def _log_to_job(job: dict, msg: str) -> None:
    for line in str(msg).splitlines() or [""]:
        job["log"].append(line)


def _args_from_request(data: dict):
    """웹 폼 값 -> crawler argparse Namespace(기본값 채움)."""
    crawler = _get_crawler()
    args = crawler.build_parser().parse_args([])  # 기본값으로 초기화
    urls = [u.strip() for u in (data.get("urls") or "").splitlines() if u.strip() and not u.strip().startswith("#")]
    args.urls = urls
    args.file = None
    args.out = str(HERE / "output")

    args.depth = int(data.get("depth") or 0)
    args.max_pages = int(data.get("max_pages") or 50)
    args.delay = float(data.get("delay") or 1.0)
    args.concurrency = int(data.get("concurrency") or 2)
    args.scroll = int(data.get("scroll") or 0)
    args.timeout = int(data.get("timeout") or 30)
    args.allow_subdomains = bool(data.get("allow_subdomains"))
    args.ignore_robots = bool(data.get("ignore_robots"))
    args.capture = data.get("capture", True) is not False
    args.show = bool(data.get("show")) or bool(data.get("manual_login"))

    # 로그인
    args.login_url = (data.get("login_url") or "").strip() or None
    args.username = (data.get("username") or "").strip() or None
    args.password = (data.get("password") or "") or None
    args.username_selector = (data.get("username_selector") or "").strip() or None
    args.password_selector = (data.get("password_selector") or "").strip() or None
    args.submit_selector = (data.get("submit_selector") or "").strip() or None
    args.manual_login = bool(data.get("manual_login"))
    sess = (data.get("session") or "").strip()
    if sess:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\.json", sess):
            raise ValueError("세션은 경로 없는 영문/숫자 .json 파일명만 허용합니다.")
        session_path = HERE / "output" / sess
        if session_path.is_symlink() or session_path.resolve().parent != (HERE / "output").resolve():
            raise ValueError("범위 밖 세션 경로는 허용하지 않습니다.")
        args.session = str(session_path)
    else:
        args.session = None
    args.keep_secrets = False

    # LLM 미사용
    args.llm = "none"
    return args, urls


def _run_job(job: dict, data: dict) -> None:
    crawler = None
    try:
        crawler = _get_crawler()
        args, urls = _args_from_request(data)
        if not urls:
            raise ValueError("시작 URL을 한 개 이상 입력하세요.")
        if args.session:
            Path(args.session).parent.mkdir(parents=True, exist_ok=True)

        job["cancel_event"] = threading.Event()
        args.cancel_event = job["cancel_event"]

        if args.manual_login:
            job["manual_event"] = threading.Event()
            job["needs_manual"] = True
            args.manual_event = job["manual_event"]

        crawler.LOG_CALLBACK = lambda m: _log_to_job(job, m)

        def _on_progress(done, total, pct):
            job["progress"] = {"done": done, "total": total, "pct": pct}
            if job["phase"] in ("ready", "login"):
                job["phase"] = "crawl"   # 로그인이 끝나고 수집이 시작됨

        crawler.PROGRESS_CALLBACK = _on_progress
        will_login = args.manual_login or bool(args.username and args.password)
        job["phase"] = "login" if will_login else "crawl"
        _log_to_job(job, f"시작: {len(urls)}개 주소 · 깊이 {args.depth} · 최대 {args.max_pages}페이지")

        results = asyncio.run(crawler.crawl(urls, args))
        job["needs_manual"] = False
        job["stopped"] = bool(job["cancel_event"] and job["cancel_event"].is_set())
        job["phase"] = "save"

        ok = sum(r.get("ok") for r in results)
        _log_to_job(job, f"수집 {'중지' if job['stopped'] else '완료'}: 성공 {ok} / 실패 {len(results) - ok}")

        out_dir, burp_count = crawler.save_outputs(results, args)
        job["out_dir"] = str(out_dir)
        for name in ["burp_history.xml", "for_claude.md", "sitemap.xml",
                     "sitemap_urls.txt", "results.json"]:
            fp = out_dir / name
            if fp.exists():
                job["files"].append({"name": name, "size": fp.stat().st_size})
        if burp_count:
            _log_to_job(job, f"요청·응답 원문 {burp_count}건 저장 (burp_history.xml)")
        _log_to_job(job, f"결과 폴더: {out_dir}")
        if not job["stopped"]:
            job["progress"]["pct"] = 100
        job["phase"] = "done"
        job["state"] = "done"
    except Exception as e:
        job["error"] = f"{type(e).__name__}: {e}"
        _log_to_job(job, "오류: " + job["error"])
        job["state"] = "error"
    finally:
        if crawler is not None:
            crawler.LOG_CALLBACK = None
            crawler.PROGRESS_CALLBACK = None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # 접속 로그 숨김
        pass

    def _send(self, code, body: bytes, ctype="application/json; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Content-Security-Policy", "frame-ancestors 'self'")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Content-Security-Policy", "frame-ancestors 'self'")
        if extra:
            for k, v in extra:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def _authorized(self, api=False):
        port = self.server.server_address[1]
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if self.headers.get("Host", "").lower() not in hosts:
            self._json({"error": "허용하지 않는 Host"}, 403)
            return False
        origin = self.headers.get("Origin")
        if origin and origin not in {"http://" + h for h in hosts}:
            self._json({"error": "허용하지 않는 Origin"}, 403)
            return False
        supplied_token = self.headers.get("X-Local-Token", "")
        if api and (not re.fullmatch(r"[0-9a-f]{64}", supplied_token) or not secrets.compare_digest(supplied_token, API_TOKEN)):
            self._json({"error": "로컬 API 인증 실패: 화면을 새로 고치세요."}, 403)
            return False
        return True

    # ---- GET ----
    def do_GET(self):
        path = urlparse(self.path).path
        if not self._authorized(api=path.startswith("/api/")):
            return
        if path in ("/", "/index.html"):
            try:
                html = UI_FILE.read_text(encoding="utf-8").replace("__LOCAL_API_TOKEN__", API_TOKEN).encode("utf-8")
            except FileNotFoundError:
                return self._send(500, b"web_ui.html not found", "text/plain; charset=utf-8")
            return self._send(200, html, "text/html; charset=utf-8")

        if path == "/detector":
            try:
                return self._send(200, _detector_html(), "text/html; charset=utf-8")
            except FileNotFoundError:
                return self._send(404, "pii_finder.html 이 같은 폴더에 없습니다.".encode("utf-8"),
                                  "text/plain; charset=utf-8")

        if path == "/api/status":
            try:
                since = max(0, int(parse_qs(urlparse(self.path).query).get("since", ["0"])[0]))
            except ValueError:
                return self._json({"error": "잘못된 since 값"}, 400)
            with JOB_LOCK:
                j = JOB
                return self._json({
                    "state": j.get("state", "idle"),
                    "log": j.get("log", [])[since:],
                    "log_total": len(j.get("log", [])),
                    "files": j.get("files", []),
                    "error": j.get("error"),
                    "needs_manual": j.get("needs_manual", False),
                    "progress": j.get("progress", {"done": 0, "total": 0, "pct": 0}),
                    "phase": j.get("phase", "ready"),
                    "stopped": j.get("stopped", False),
                    "run": os.path.basename(j.get("out_dir") or ""),
                })

        if path == "/api/outputs":
            info = _list_outputs()
            return self._json({
                "runs": len(info["runs"]),
                "sessions": len(info["sessions"]),
                "bytes": info["bytes"],
            })

        if path == "/api/download":
            name = parse_qs(urlparse(self.path).query).get("name", [""])[0]
            with JOB_LOCK:
                out_dir = JOB.get("out_dir")
            if not out_dir or name not in DOWNLOAD_NAMES:
                return self._send(404, b"not found", "text/plain")
            fp = Path(out_dir) / name
            if fp.is_symlink() or not fp.is_file() or fp.resolve().parent != Path(out_dir).resolve():
                return self._send(404, b"not found", "text/plain")
            ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
            return self._send(200, fp.read_bytes(), ctype,
                              extra=[("Content-Disposition", f'attachment; filename="{name}"')])

        return self._send(404, b"not found", "text/plain")

    # ---- POST ----
    def do_POST(self):
        path = urlparse(self.path).path
        if not self._authorized(api=True):
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            return self._json({"error": "application/json 요청만 허용합니다."}, 415)
        if self.headers.get("Transfer-Encoding"):
            return self._json({"error": "Transfer-Encoding 미지원"}, 400)
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return self._json({"error": "잘못된 Content-Length"}, 400)
        if length < 0 or length > MAX_BODY_BYTES:
            return self._json({"error": "요청 본문 크기 제한 초과"}, 413)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
            if not isinstance(data, dict):
                raise ValueError("JSON object required")
        except (UnicodeError, ValueError):
            return self._json({"error": "잘못된 JSON 객체"}, 400)

        if path == "/api/start":
            with JOB_LOCK:
                if JOB.get("state") == "running" or JOB.get("state") == "waiting_login":
                    return self._json({"error": "이미 실행 중입니다."}, 409)
                globals()["JOB"] = _new_job()
                job = JOB
            threading.Thread(target=_run_job, args=(job, data), daemon=True).start()
            return self._json({"ok": True})

        if path == "/api/clear":
            # 실행 중에는 지우지 않는다(수집 중인 파일을 건드리지 않기 위해)
            with JOB_LOCK:
                if JOB.get("state") in ("running", "waiting_login"):
                    return self._json({"error": "수집이 진행 중입니다. 먼저 중지하거나 끝날 때까지 기다려 주세요."}, 409)
                result = {"removed_runs": 0, "removed_sessions": 0, "freed_bytes": 0}
                if data.get("delete_files", True):
                    result = _clear_outputs(bool(data.get("sessions")))
                globals()["JOB"] = {"state": "idle"}
            return self._json({"ok": True, **result})

        if path == "/api/login_done":
            with JOB_LOCK:
                ev = JOB.get("manual_event")
                JOB["needs_manual"] = False
            if ev:
                ev.set()
            return self._json({"ok": True})

        if path == "/api/stop":
            with JOB_LOCK:
                cev = JOB.get("cancel_event")
                mev = JOB.get("manual_event")
                JOB["needs_manual"] = False
            if cev:
                cev.set()
            if mev:
                mev.set()  # 수동 로그인 대기 중이면 풀어 주고 중지로 이어지게
            return self._json({"ok": True})

        return self._send(404, b"not found", "text/plain")


def main():
    ap = argparse.ArgumentParser(description="웹 크롤러 로컬 UI")
    ap.add_argument("--port", type=int, default=8777)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--open", action="store_true", help="시작 시 브라우저 자동 열기")
    a = ap.parse_args()
    if a.host not in ("127.0.0.1", "localhost"):
        ap.error("로컬 UI는 127.0.0.1 또는 localhost에서만 실행할 수 있습니다.")
    url = f"http://{a.host}:{a.port}/"
    print(f"웹 크롤러 UI 실행 중 → {url}")
    print("종료하려면 Ctrl+C 를 누르세요. (모든 처리는 이 PC 안에서만 이뤄집니다)")
    if a.open:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n종료합니다.")


if __name__ == "__main__":
    main()
