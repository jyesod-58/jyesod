// Full local workflow checks using generated synthetic Burp fixtures.
// node tests/test_large_workflow_browser.js [/tmp/burp-large-fixtures]
const fs=require('fs'),path=require('path'),assert=require('assert');
const {chromium}=require('playwright');
const fixtures=process.argv[2]||'/tmp/burp-large-fixtures';
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',args:['--no-sandbox'],headless:true});
 const result={};
 try{
  const context=await browser.newContext(),page=await context.newPage(),errors=[],external=[];
  page.on('pageerror',error=>errors.push(String(error)));page.on('dialog',dialog=>dialog.accept());
  let html=fs.readFileSync(path.resolve(__dirname,'../pii_finder.html'),'utf8');
  const marker='setLoaded(false);\n})();';assert(html.includes(marker));
  html=html.replace(marker,'setLoaded(false);window.audit={S,goHome,hydratePage,largeProjectBlob,restoreLargeProjectFile,reviewKey,clearPayloadStore,purgeAllPayloadStores,busy:()=>reading||preparing||analysisBusy};\n})();');
  await context.route('**/*',route=>{
   if(route.request().url()==='http://127.0.0.1:8798/')return route.fulfill({contentType:'text/html',body:html});
   external.push(route.request().url());return route.abort();
  });
  await page.goto('http://127.0.0.1:8798/');
  async function reset(){await page.evaluate(async()=>{audit.goHome();await audit.clearPayloadStore();});}
  async function importFile(filename){
   await reset();const started=Date.now();
   await page.locator('#file').setInputFiles(path.join(fixtures,filename));
   await page.waitForFunction(()=>!audit.busy(),{},{timeout:240000});
   return (Date.now()-started)/1000;
  }
  const manifest=JSON.parse(fs.readFileSync(path.join(fixtures,'100MiB-records.xml.manifest.json'),'utf8'));
  result.importSeconds=await importFile('100MiB-records.xml');
  const before=await page.evaluate(()=>({count:audit.S.pages.length,hashes:audit.S.pages.map(p=>p.responseHash),sourceHashes:[...new Set(audit.S.pages.map(p=>p.sourceHash))],failures:audit.S.importFailures.length,allStored:audit.S.pages.every(p=>p.payloadKey&&!p.text&&!p.rawResponseBase64)}));
  assert.equal(before.count,manifest.expected_items);assert.equal(before.count,74);assert.deepEqual(before.sourceHashes,[manifest.sha256]);assert.equal(before.failures,0);assert(before.allStored);
  const roundtripStarted=Date.now();
  result.roundtrip=await page.evaluate(async()=>{
   const first=audit.S.findings.find(f=>f.pi===0),last=audit.S.findings.find(f=>f.pi===audit.S.pages.length-1);
   if(!first||!last)throw new Error('Expected first/last synthetic findings');
   audit.S.reviews.set(audit.reviewKey(first),'true');audit.S.reviews.set(audit.reviewKey(last),'false');
   const expectedReviews=JSON.stringify([...audit.S.reviews]),raw=await audit.hydratePage(audit.S.pages[0]);
   const expectedRaw=raw.rawResponseBase64;
   const blob=await audit.largeProjectBlob();const file=new File([blob],'synthetic-100MiB-project.jsonl',{type:'application/x-ndjson'});
   await audit.restoreLargeProjectFile(file);const restored=await audit.hydratePage(audit.S.pages[0]);
   return {count:audit.S.pages.length,bytes:blob.size,hashes:audit.S.pages.map(p=>p.responseHash),sourceHashes:[...new Set(audit.S.pages.map(p=>p.sourceHash))],reviewsPreserved:JSON.stringify([...audit.S.reviews])===expectedReviews,originalWirePreserved:restored.rawResponseBase64===expectedRaw,allStored:audit.S.pages.every(p=>p.payloadKey&&!p.text&&!p.rawResponseBase64),failures:audit.S.importFailures.length};
  });
  result.roundtripSeconds=(Date.now()-roundtripStarted)/1000;
  assert.equal(result.roundtrip.count,74);assert.deepEqual(result.roundtrip.hashes,before.hashes);assert.deepEqual(result.roundtrip.sourceHashes,before.sourceHashes);assert.equal(result.roundtrip.reviewsPreserved,true);assert.equal(result.roundtrip.originalWirePreserved,true);assert.equal(result.roundtrip.allStored,true);assert.equal(result.roundtrip.failures,0);
  console.log('PASS 100MiB/74-record JSONL project round trip preserves every response hash, original wire data and review decisions');
  // Clone before truncating. Source fixture is never changed.
  const truncated=path.join(fixtures,'80MiB-truncated-workflow.xml');fs.copyFileSync(path.join(fixtures,'80MiB.xml'),truncated);fs.truncateSync(truncated,fs.statSync(truncated).size-20);
  try{
   result.truncatedSeconds=await importFile(path.basename(truncated));
   result.truncated=await page.evaluate(()=>({count:audit.S.pages.length,sources:audit.S.sources.map(s=>({fullyRead:s.fullyRead,items:s.items,hash:s.sha256})),failures:audit.S.importFailures.length,stored:audit.S.pages.every(p=>p.payloadKey)}));
   assert.equal(result.truncated.count,1);assert(result.truncated.sources.some(s=>s.fullyRead===false));assert(result.truncated.failures>=1);assert.equal(result.truncated.stored,true);
   console.log('PASS truncated 80MiB XML preserves its valid transaction and marks source/file incomplete');
  }finally{fs.unlinkSync(truncated);}
  await reset();await page.locator('#file').setInputFiles(path.join(fixtures,'500MiB-records.xml'));
  await page.waitForFunction(()=>audit.busy(),{},{timeout:15000});await page.waitForTimeout(100);
  await page.evaluate(async()=>{audit.goHome();await audit.clearPayloadStore();});await page.waitForTimeout(500);
  result.cancelled=await page.evaluate(()=>({count:audit.S.pages.length,busy:audit.busy(),large:audit.S.largeMode}));
  assert.equal(result.cancelled.count,0);assert.equal(result.cancelled.busy,false);assert.equal(result.cancelled.large,false);
  console.log('PASS cancelling active 500MiB import leaves an empty idle project');
  await page.evaluate(async()=>await audit.purgeAllPayloadStores());
  assert.deepEqual(errors,[]);assert.deepEqual(external,[]);result.errors=errors;result.external=external;result.browser=await browser.version();
  console.log(JSON.stringify({...result,roundtrip:{...result.roundtrip,hashes:undefined,responseHashesPreserved:result.roundtrip.hashes.length}},null,2));
 }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
