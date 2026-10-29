"""Actual stdlib server + browser smoke; loopback traffic and synthetic data only."""
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1]
with socket.socket() as s:
    s.bind(('127.0.0.1',0));port=s.getsockname()[1]
process=subprocess.Popen([sys.executable,str(ROOT/'webapp.py'),'--port',str(port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
url=f'http://127.0.0.1:{port}'
def request(path,headers=None):
    try:
        with opener.open(urllib.request.Request(url+path,headers=headers or {}),timeout=3) as r:return r.status,r.read(),r.headers
    except urllib.error.HTTPError as e:return e.code,e.read(),e.headers
try:
    for i in range(100):
        if process.poll() is not None:raise AssertionError('local server exited')
        try:status,body,headers=request('/');break
        except (urllib.error.URLError,ConnectionError):time.sleep(.05)
    else:raise AssertionError('local server did not start')
    assert status==200
    assert '__LOCAL_API_TOKEN__' not in body.decode()
    assert headers['Cache-Control']=='no-store'
    token=re.search(r"const API_TOKEN\s*=\s*['\"]([0-9a-f]{64})",body.decode()).group(1)
    assert request('/api/status')[0]==403
    assert request('/api/status',{'X-Local-Token':token})[0]==200
    assert request('/api/status',{'X-Local-Token':token,'Origin':'https://foreign.example.test'})[0]==403
    assert request('/',{'Host':'foreign.example.test'})[0]==403
    with sync_playwright() as p:
        browser=p.chromium.launch(executable_path='/usr/bin/chromium',args=['--no-sandbox'],headless=True)
        context=browser.new_context()
        external=[]
        def route(r):
            if r.request.url.startswith(url+'/'):r.continue_()
            else:external.append(r.request.url);r.abort()
        context.route('**/*',route)
        page=context.new_page();errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
        page.goto(url+'/')
        frame=page.frame_locator('#detFrame')
        frame.locator('#paste').fill(json.dumps([{'url':'https://agency.example.test/profile','body':{'user_nm':'가상회원','email':'member@example.test'}}],ensure_ascii=False))
        frame.locator('#loadPaste').click()
        frame.locator('.detail-open').first.wait_for()
        page.wait_for_timeout(300)
        coverage=frame.locator('#coverageSummary').text_content()
        assert '입력 1개' in coverage,repr(coverage)+' errors='+repr(errors)
        assert not errors,errors
        assert not external,external
        browser.close()
    print('PASS actual local server startup without crawler dependencies, token/Origin/Host/no-store, embedded detector and synthetic import')
finally:
    process.terminate()
    try:process.wait(timeout=5)
    except subprocess.TimeoutExpired:process.kill();process.wait()
