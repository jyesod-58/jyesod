// Full browser import/storage integration using generated synthetic files only.
const fs=require('fs'),path=require('path'),assert=require('assert');
const {chromium}=require('playwright');
const fixtures=process.argv[2]||'/tmp/burp-large-fixtures';
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',args:['--no-sandbox'],headless:true});
 const results=[];
 try{
  const context=await browser.newContext(),page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(String(e)));page.on('dialog',d=>d.accept());
  let html=fs.readFileSync(path.resolve(__dirname,'../pii_finder.html'),'utf8');
  html=html.replace('setLoaded(false);\n})();','setLoaded(false);window.audit={S,D,goHome,hydratePage,largeProjectBlob,restoreLargeProjectFile,updateSearch,reviewKey,clearPayloadStore,busy:()=>reading||preparing||analysisBusy};\n})();');
  const external=[];await context.route('**/*',route=>{if(route.request().url()==='http://127.0.0.1:8799/')return route.fulfill({contentType:'text/html',body:html});external.push(route.request().url());return route.abort();});
  await page.goto('http://127.0.0.1:8799/');
  async function importFile(name){
    await page.evaluate(async()=>{audit.goHome();await audit.clearPayloadStore();});
    const start=Date.now();await page.locator('#file').setInputFiles(path.join(fixtures,name));
    const interval=setInterval(async()=>{try{console.log('PROGRESS '+name+' '+await page.locator('#fileStatus').textContent());}catch{}},15000);
    try{await page.waitForFunction(()=>!audit.busy(),{},{timeout:240000});}finally{clearInterval(interval);}
    const actual=await page.evaluate(()=>({pages:audit.S.pages.length,large:audit.S.largeMode,failures:audit.S.importFailures.map(x=>x.reason),coverage:audit.S.pages.map(p=>p.analysis?.state),inMemory:audit.S.pages.some(p=>p.text||p.rawResponseBase64),stored:audit.S.pages.every(p=>p.payloadKey),hashes:[...new Set(audit.S.pages.map(p=>p.sourceHash))],status:document.querySelector('#fileStatus').textContent}));
    actual.name=name;actual.seconds=(Date.now()-start)/1000;results.push(actual);return actual;
  }
  for(const name of ['80MiB.xml','100MiB-records.xml','500MiB.xml','500MiB-records.xml']){
    const manifest=JSON.parse(fs.readFileSync(path.join(fixtures,name+'.manifest.json'),'utf8'));
    const r=await importFile(name);assert.equal(r.pages,manifest.expected_items,JSON.stringify(r));assert.equal(r.failures.length,0,JSON.stringify(r));assert(r.coverage.every(x=>x==='complete'),JSON.stringify(r));assert.equal(r.large,true);assert.equal(r.inMemory,false);assert.equal(r.stored,true);assert.deepEqual(r.hashes,[manifest.sha256]);console.log('PASS '+name+' '+r.pages+' records in '+r.seconds+' sec');
    assert(await page.evaluate(async()=>{const p=await audit.hydratePage(audit.S.pages[0]);return !!p.text;}));
  }
  let r=await importFile('500MiB-plus1.xml');assert.equal(r.pages,0);assert(r.failures.some(x=>x.includes('500MiB')));console.log('PASS 500MiB + 1 byte rejected explicitly');
  r=await importFile('2MiB-cdata-boundary.xml');assert.equal(r.failures.length,0);assert(r.pages>0);console.log('PASS CDATA/chunk boundary XML');
  // Use the 80MiB file (one small record plus padding) for project round-trip/search/UI.
  await importFile('80MiB.xml');
  const roundtrip=await page.evaluate(async()=>{
    const first=audit.S.findings[0];if(first)audit.S.reviews.set(audit.reviewKey(first),'true');
    const blob=await audit.largeProjectBlob(),file=new File([blob],'project.jsonl',{type:'application/x-ndjson'});await audit.restoreLargeProjectFile(file);
    return {pages:audit.S.pages.length,reviews:[...audit.S.reviews.values()],stored:audit.S.pages.every(p=>p.payloadKey)};
  });assert.equal(roundtrip.pages,1);assert.equal(roundtrip.stored,true);assert(roundtrip.reviews.includes('true'));
  await page.locator('.detail-open').first().click();await page.waitForFunction(()=>!document.querySelector('#drawer').hidden);assert.equal(await page.locator('#dMaskChk').isChecked(),true);await page.locator('#dClose').click();
  console.log('PASS disk-backed project JSONL round trip, reviews and masked drawer');
  assert.equal(errors.length,0,errors.join('\n'));assert.equal(external.length,0);await page.evaluate(async()=>{audit.goHome();await audit.clearPayloadStore();});
  fs.writeFileSync(path.join(__dirname,'validation-large-browser.json'),JSON.stringify({results,roundtrip,errors,external,browser:await browser.version()},null,2));
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
