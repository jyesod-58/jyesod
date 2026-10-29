// IndexedDB storage regression checks with local synthetic data only.
const fs=require('fs');const path=require('path');const assert=require('assert');
const {chromium}=require('playwright');
const source=fs.readFileSync(path.join(__dirname,'../large_storage_fragment.js'),'utf8');
const expose=`\nwindow.payloadTest={storePagePayload,hydratePage,clearPayloadStore,estimatePayloadStorage,requestPersistence,purgeAllPayloadStores,dbName:PAYLOAD_DB_NAME,session:PAYLOAD_SESSION_ID};`;
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
 try{
  const context=await browser.newContext();const page=await context.newPage();const errors=[];
  page.on('pageerror',error=>errors.push(String(error)));
  await context.route('http://localhost:9913/**',r=>r.fulfill({status:200,contentType:'text/html',body:'<!doctype html><title>Offline payload test</title>'}));
  await page.goto('http://localhost:9913/');await page.evaluate(source+expose);
  const results=await page.evaluate(async()=>{
   const a=payloadTest,results=[];
   const check=(name,value)=>{if(!value)throw new Error(name);results.push(name);};
   const original='SYNTHETIC_BODY_'.repeat(300000),pg={url:'https://example.test/data',status:200,text:original,rawResponseBase64:'QUJD',originalResponseBase64:'REVG',request:'GET /synthetic HTTP/1.1',harBodyBase64:'R0hJ',harHead:'synthetic header',originalHeaders:'original header'};
   check('store returns same metadata object',await a.storePagePayload(pg)===pg);
   check('all payload fields removed from metadata',['text','rawResponseBase64','originalResponseBase64','request','harBodyBase64','harHead','originalHeaders'].every(k=>!Object.hasOwn(pg,k)));
   check('response summary retained',pg.hasResponse===true&&pg.textLength===original.length&&!!pg.payloadKey);
   let hydrated=await a.hydratePage(pg);check('hydrate returns separate complete object',hydrated!==pg&&hydrated.text===original&&hydrated.request==='GET /synthetic HTTP/1.1'&&hydrated.harBodyBase64==='R0hJ');hydrated=null;
   const previousKey=pg.payloadKey;await a.storePagePayload(pg);check('repeated metadata-only store is idempotent',pg.payloadKey===previousKey);
   pg.request='updated synthetic request';await a.storePagePayload(pg);hydrated=await a.hydratePage(pg);check('partial overwrite preserves previous stored fields',hydrated.text===original&&hydrated.request==='updated synthetic request');hydrated=null;
   const rawPut=IDBObjectStore.prototype.put;
   IDBObjectStore.prototype.put=function(){throw new DOMException('DO_NOT_LEAK_SYNTHETIC_SECRET','QuotaExceededError');};
   const quotaPage={text:'synthetic retained body'};let quota;
   try{await a.storePagePayload(quotaPage);}catch(error){quota=error;}
   finally{IDBObjectStore.prototype.put=rawPut;}
   check('quota failure keeps original data',quotaPage.text==='synthetic retained body'&&!quotaPage.payloadKey);
   check('quota error is Korean and excludes original diagnostic',quota?.message.includes('공간')&&!quota.message.includes('DO_NOT_LEAK'));
   const stalePage={text:'stale synthetic'},stale=a.storePagePayload(stalePage),clear=a.clearPayloadStore();
   const outcomes=await Promise.allSettled([stale,clear]);check('clear invalidates queued store before mutation',outcomes[0].status==='rejected'&&outcomes[0].reason.code==='cancelled'&&outcomes[1].status==='fulfilled'&&stalePage.text==='stale synthetic');
   let missing;try{await a.hydratePage(pg);}catch(error){missing=error;}
   check('clear removes current-session payload',missing?.code==='missing');
   const fresh={text:'new synthetic'};await a.storePagePayload(fresh);check('new stores work after awaited clear',(await a.hydratePage(fresh)).text==='new synthetic');
   const noStore={text:'memory mode'};check('memory-only hydrate creates clone without storing',(await a.hydratePage(noStore)).text==='memory mode'&&!noStore.payloadKey);
   const estimate=await a.estimatePayloadStorage();check('capacity estimate contains only metadata',Object.keys(estimate).sort().join(',')==='available,availableBytes,persistent,quotaBytes,usageBytes');
   window.firstPageStored=fresh;
   return results;
  });
  const second=await context.newPage();await second.goto('http://localhost:9913/');await second.evaluate(source+expose);
  await second.evaluate(async()=>{window.secondStored={text:'other tab synthetic'};await payloadTest.storePagePayload(secondStored);});
  await page.evaluate(async()=>await payloadTest.clearPayloadStore());
  assert.equal(await second.evaluate(async()=>(await payloadTest.hydratePage(secondStored)).text),'other tab synthetic');results.push('clearing one tab does not delete another session');
  await page.evaluate(async()=>{window.purgeFirst={text:'first session purge synthetic'};await payloadTest.storePagePayload(purgeFirst);await payloadTest.purgeAllPayloadStores();});
  const firstMissing=await page.evaluate(async()=>{try{await payloadTest.hydratePage(purgeFirst);return false;}catch(error){return error.code==='missing';}});
  const secondMissing=await second.evaluate(async()=>{try{await payloadTest.hydratePage(secondStored);return false;}catch(error){return error.code==='missing';}});
  assert(firstMissing&&secondMissing);results.push('explicit purge removes payloads across all sessions');
  assert.deepEqual(errors,[]);console.log(results.map(x=>'PASS '+x).join('\n'));console.log(results.length+' local storage checks passed');
 }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
