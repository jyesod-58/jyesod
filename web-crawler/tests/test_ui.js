// Browser regression checks with synthetic data. Run: node tests/test_ui.js [path/to/pii_finder.html]
const fs=require('fs');
const path=require('path');
const assert=require('assert');
const {chromium}=require('playwright');
const input=process.argv[2]||path.join(__dirname,'../pii_finder.html');
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
 try{
  const page=await browser.newPage();const errors=[];const requests=[];
  page.on('pageerror',e=>errors.push(String(e)));await page.route(/https?:\/\//,r=>{requests.push(r.request().url());return r.abort();});
  let html=fs.readFileSync(input,'utf8');
  const marker='setLoaded(false);\n})();';assert(html.includes(marker),'test harness anchor exists');
  html=html.replace(marker,'setLoaded(false);window.audit={S,D,loadPages,reviewKey,projectSnapshot,restoreProject,maskedReport,defaultReviewStatus,renderCoverage,maskVal};\n})();');
  await page.setContent(html);page.on('dialog',d=>d.accept());
  const initial=await page.evaluate(()=>({candidates:audit.S.candidates,assets:audit.S.skipAssets,operator:audit.S.operatorInference,defaultReview:audit.defaultReviewStatus({tier:'high'}),rrn:audit.maskVal('rrn','990101-1234567')}));
  assert.deepEqual(initial,{candidates:true,assets:false,operator:false,defaultReview:'pending',rrn:'99***********'});
  await page.evaluate(async()=>{
   await audit.loadPages([{url:'https://agency.example.test/profile?token=DO_NOT_LEAK_SYNTHETIC_SECRET',fileName:'synthetic.xml',fileItem:1,sourceId:1,method:'GET',status:200,text:'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"email":"person@example.test"}',analysis:{state:'complete',reasons:[]}}],false,1);
   const finding=audit.S.findings.find(f=>f.type==='email');audit.S.reviews.set(audit.reviewKey(finding),'true');
  });
  await page.locator('.detail-open').first().click();assert.equal(await page.evaluate(()=>audit.D.mask),true);assert(!await page.locator('#dBody').innerText().then(t=>t.includes('person@example.test')));await page.locator('#dClose').click();
  const roundtrip=await page.evaluate(async()=>{
   const snapshot=JSON.parse(JSON.stringify(audit.projectSnapshot()));
   audit.S.pages[0].analysis={state:'failed',reasons:['Unexpected token DO_NOT_LEAK_SYNTHETIC_SECRET']};
   const report=JSON.stringify(audit.maskedReport());await audit.restoreProject(snapshot);
   return {pages:audit.S.pages.length,reviews:[...audit.S.reviews.values()],leaks:report.includes('person@example.test')||report.includes('DO_NOT_LEAK_SYNTHETIC_SECRET'),coverageHidden:document.querySelector('#coveragePanel').hidden};
  });
  assert.equal(roundtrip.pages,1);assert(roundtrip.reviews.includes('true'));assert.equal(roundtrip.leaks,false);assert.equal(roundtrip.coverageHidden,false);
  const projectDownload=page.waitForEvent('download');await page.locator('#saveProject').click();assert.equal((await projectDownload).suggestedFilename(),'pii-review-project.json');
  const reportDownload=page.waitForEvent('download');await page.locator('#saveReport').click();assert.equal((await reportDownload).suggestedFilename(),'pii-review-masked-report.json');
  assert.equal(errors.length,0,errors.join('\n'));assert.equal(requests.length,0);
  console.log('PASS conservative defaults, detail masking, project round trip, masked report, local downloads, no external requests');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
