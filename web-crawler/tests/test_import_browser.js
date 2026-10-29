// Offline synthetic end-to-end import regression tests. No target hosts contacted.
const fs=require('fs'),path=require('path'),assert=require('assert'),zlib=require('zlib'),crypto=require('crypto');
const {chromium}=require('playwright');
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
 let passed=0;const checks=[],skipped=[];
 try{
  const page=await browser.newPage(),errors=[],requests=[];page.on('pageerror',e=>errors.push(String(e)));page.on('dialog',d=>d.accept());
  await page.route('**/*',route=>{requests.push(route.request().url());return route.abort();});
  let html=fs.readFileSync(path.join(__dirname,'../pii_finder.html'),'utf8');
  html=html.replace('setLoaded(false);\n})();','setLoaded(false);window.audit={S,D,load,loadPages,toPages,rescan,toggleAssets,goHome,sha256bytes,activeFindings,projectSnapshot,restoreProject,maskedReport,coverageData};\n})();');
  await page.setContent(html);
  const raw=(body,mime='application/json',extra='',status=200)=>Buffer.concat([Buffer.from(`HTTP/1.1 ${status} Synthetic\r\nContent-Type: ${mime}\r\n${extra}\r\n`),Buffer.isBuffer(body)?body:Buffer.from(body)]);
  const item=(bytes,status=200,url='https://agency.example.test/profile')=>`<item><url>${url}</url><method>GET</method><status>${status}</status><time>synthetic</time><request base64="true">${Buffer.from('GET /profile HTTP/1.1\r\n\r\n').toString('base64')}</request><response base64="true">${bytes.toString('base64')}</response></item>`;
  const xml=items=>'<?xml version="1.0"?><items>'+items+'</items>';
  const email='member@example.test',json=JSON.stringify({user_nm:'가상회원',email,phone:'+82-10-0000-0000'});
  async function load(data){return page.evaluate(async data=>{audit.goHome();const ok=await audit.load(data,'synthetic.xml',false);return {ok,pages:audit.S.pages.map(p=>({analysis:p.analysis,status:p.status,hash:p.responseHash,view:p.text,raw:p.rawResponseBase64})),findings:audit.S.findings.map(f=>({type:f.type,source:f.source,tier:f.tier})),coverage:audit.coverageData()};},data);}
  function pass(name){checks.push(name);passed++;console.log('PASS '+name);}
  let r=await load(xml(item(raw(json))));assert(r.ok);assert.equal(r.pages.length,1);assert(r.findings.some(f=>f.type==='name'));assert.equal(r.pages[0].analysis.state,'complete');pass('Burp XML base64 normal import and normalized keys');
  for(const [encoding,compress] of [['gzip',zlib.gzipSync],['deflate',zlib.deflateSync],['br',zlib.brotliCompressSync]]){
   const bytes=raw(compress(Buffer.from(json)),'application/json',`Content-Encoding: ${encoding}\r\n`);r=await load(xml(item(bytes)));assert(r.ok);
   if(r.pages[0].analysis.state==='unsupported'){assert.equal(encoding,'br');pass('Brotli unsupported browser explicitly accounted');}
   else{assert.equal(r.pages[0].analysis.state,'complete');assert(r.findings.some(f=>f.type==='email'));assert.equal(r.pages[0].hash,crypto.createHash('sha256').update(bytes).digest('hex'));assert.equal(r.pages[0].raw,bytes.toString('base64'));pass(encoding+' decoded and original wire evidence/hash retained');}
  }
  const b=Buffer.from(json),chunked=Buffer.concat([Buffer.from(b.length.toString(16)+'\r\n'),b,Buffer.from('\r\n0\r\n\r\n')]);r=await load(xml(item(raw(chunked,'application/json','Transfer-Encoding: chunked\r\n'))));assert.equal(r.pages[0].analysis.state,'complete');assert(r.findings.some(f=>f.type==='email'));pass('chunked transfer de-framing');
  r=await load(xml(item(raw(JSON.stringify({email})))+'<item><url>https://agency.example.test/bad</url><response base64="true">%%%INVALID%%%</response></item>'));assert.equal(r.pages.length,2);assert.equal(r.pages[0].analysis.state,'complete');assert.equal(r.pages[1].analysis.state,'failed');assert(r.findings.some(f=>f.type==='email'));pass('one bad Base64 item isolated with good item retained');
  r=await load(xml(item(raw(JSON.stringify({email})))+item(raw(JSON.stringify({email}),'application/json','',500),500)));assert.equal(r.pages.length,2);assert.deepEqual(r.pages.map(p=>p.status),[200,500]);assert.equal(r.findings.filter(f=>f.type==='email').length,2);pass('same URL/body distinct 200 and 500 transactions retained');
  let n=await page.evaluate(()=>{audit.S.statusFilter='2xx';return audit.activeFindings().filter(f=>f.type==='email').length;});assert.equal(n,1);pass('2xx display filter preserves original transactions');
  for(const [label,body,mime,type] of [
   ['inline script','<html><body><script>window.profile={"email":"'+email+'","usernm":"가상회원"};</script></body></html>','text/html','email'],
   ['HTML attribute','<html><body><div data-email="'+email+'">profile</div></body></html>','text/html','email'],
   ['HTML entity attribute','<html><body><div data-email="member&#64;example.test">profile</div></body></html>','text/html','email'],
   ['XML attribute','<profile email="'+email+'"/>','application/xml','email'],
   ['WebSquare XML','<?xml version="1.0"?><root xmlns:w2="urn:websquare"><email>'+email+'</email></root>','application/xml','email'],
   ['script static response','const email="'+email+'";','application/javascript','email']]){
    r=await load(xml(item(raw(body,mime))));assert(r.findings.some(f=>f.type===type),label);assert.equal(r.pages[0].analysis.state,'complete');pass(label+' inspected as inert text');
  }
  r=await load(xml(item(raw('{}','application/json',`X-User-Email: ${email}\r\n`))));assert(r.findings.some(f=>f.type==='email'&&f.source==='응답 헤더'));pass('response header-only finding');
  r=await load(xml(item(raw('['.repeat(10000)+'"'+email+'"'+']'.repeat(10000)))));assert(r.ok);assert.equal(r.pages[0].analysis.state,'partial');assert(r.pages[0].analysis.reasons.some(x=>x.includes('깊이')));pass('deep JSON bounded and marked partial without stack overflow');
  r=await load(xml(item(raw('%PDF synthetic','application/pdf'))));assert.equal(r.pages[0].analysis.state,'unsupported');pass('PDF explicitly unsupported rather than clean result');
  r=await load(xml('<item><url>https://agency.example.test/no-response</url></item>'));assert.equal(r.pages[0].analysis.state,'empty');pass('missing response explicitly accounted');
  r=await load(xml(item(raw('const email="'+email+'";','application/javascript'))));
  await page.evaluate(()=>audit.toggleAssets(true));assert.equal(await page.evaluate(()=>audit.S.pages[0].analysis.state),'excluded');await page.evaluate(()=>audit.toggleAssets(false));assert.equal(await page.evaluate(()=>audit.S.pages[0].analysis.state),'complete');pass('asset mode cached coverage follows selected scope');
  const wire=raw(zlib.gzipSync(Buffer.from(JSON.stringify({email}))),'application/json','Content-Encoding: gzip\r\n');const normalized=raw(JSON.stringify({email}));
  r=await load(xml(item(normalized).replace('</item>',`<originalResponse base64="true">${wire.toString('base64')}</originalResponse><normalization>test-normalized</normalization></item>`)));assert.equal(r.pages[0].hash,crypto.createHash('sha256').update(wire).digest('hex'));pass('normalized import hash links to original wire response');
  const hashes=await page.evaluate(async()=>[await audit.sha256bytes(new Uint8Array()),await audit.sha256bytes(new TextEncoder().encode('abc'))]);assert.deepEqual(hashes,['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855','ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad']);pass('SHA-256 known vectors');
  // EUC-KR bytes for {"usernm":"가상회원"}, generated from Python codec.
  // Use a smaller unambiguous Korean value byte sequence to check charset decoding.
  const eucBody=Buffer.concat([Buffer.from('{"usernm":"'),Buffer.from([0xb0,0xa1,0xbb,0xf3,0xc8,0xb8,0xbf,0xf8]),Buffer.from('"}')]);
  r=await load(xml(item(raw(eucBody,'application/json; charset=euc-kr'))));assert(r.pages[0].view.includes('가상회원'));assert(r.findings.some(f=>f.type==='name'));pass('EUC-KR response decoded without corrupting raw bytes');
  // Actual file chooser path exercises byte hash + FileReader and multi-file error accounting.
  await page.evaluate(()=>audit.goHome());const data=Buffer.from(xml(item(raw(JSON.stringify({email})))));
  await page.locator('#file').setInputFiles([{name:'valid.xml',mimeType:'application/xml',buffer:data},{name:'invalid.xml',mimeType:'application/xml',buffer:Buffer.from('<items><item></items>')}]);
  await page.waitForFunction(()=>document.querySelector('#file').disabled===false&&window.audit.S.pages.length===1);
  const actual=await page.evaluate(()=>({hash:audit.S.pages[0].sourceHash,failures:audit.S.importFailures.length,report:audit.maskedReport()}));assert.equal(actual.hash,crypto.createHash('sha256').update(data).digest('hex'));assert.equal(actual.failures,1);assert.equal(actual.report.coverage.failedFiles,1);pass('actual file import SHA and failed-file accounting');
  const direct=await browser.newPage();const directErrors=[];direct.on('pageerror',e=>directErrors.push(String(e)));await direct.route(/https?:\/\//,r=>{requests.push(r.request().url());return r.abort();});
  try{
    await direct.goto('file://'+path.resolve(__dirname,'../pii_finder.html'));await direct.locator('#file').setInputFiles(path.resolve(__dirname,'../sample_burp.xml'));await direct.waitForFunction(()=>document.querySelector('#file').disabled===false&&document.querySelector('#coverageSummary').textContent.includes('입력 3개'));assert.equal(directErrors.length,0,directErrors.join('\n'));pass('standalone file-open and sample XML import');
  }catch(e){if(!String(e).includes('ERR_BLOCKED_BY_ADMINISTRATOR'))throw e;skipped.push('file:// navigation blocked by managed-browser policy; local HTTP server verified separately');console.log('SKIP file:// navigation: managed-browser policy');}finally{await direct.close();}
  assert.equal(errors.length,0,errors.join('\n'));assert.equal(requests.length,0);pass('no browser script errors or external requests');
  fs.writeFileSync(path.join(__dirname,'validation-import.json'),JSON.stringify({passed,checks,skipped,browser:await browser.version()},null,2));
  console.log(passed+' browser import checks passed.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
