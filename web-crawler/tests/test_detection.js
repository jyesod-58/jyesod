// Offline detector regression tests. No target website or real personal data.
const fs=require('fs');
const path=require('path');
const assert=require('assert');
const input=process.argv[2]||path.join(__dirname,'../pii_finder.html');
const html=fs.readFileSync(input,'utf8');
let code=html.slice(html.indexOf('/* ===== 검증 함수 ===== */'),html.indexOf('let searchCache='));
if(!/\b(?:let|const|var)\s+scanBudgetDiagnostics\b/.test(code))code='let scanBudgetDiagnostics=null;\n'+code;
const host=html.match(/function hostOf\(value\)\{[^\n]+\}/)[0];
const api=new Function(code+'\n'+host+`\nreturn {
  scan(data,custom=[]){S.pages=[{url:'https://example.test/synthetic',text:JSON.stringify(data)}];const diagnostics=[];return {hits:scanAll({custom,diagnostics}),diagnostics};},
  matches(value){const diagnostics=[];scanBudgetDiagnostics=diagnostics;const hits=STRUCT.find(d=>d.id==='email').find(value);scanBudgetDiagnostics=null;return {hits,diagnostics};}
};`)();
let passed=0;
function test(name,fn){fn();passed++;console.log('PASS '+name);}
function found(data,type){return api.scan(data).hits.filter(f=>f.type===type);}

for(const key of ['usernm','user_nm','userName','name','fullName'])test('personal-name key '+key,()=>{
  assert.equal(found({[key]:'가상회원'},'name').length,1);
});
test('generic name stays candidate',()=>assert.equal(found({name:'가상회원'},'name')[0].tier,'candidate'));
test('username login ID keeps account type',()=>assert.equal(found({userName:'demo_reader'},'id').length,1));
test('custom key normalizes separators',()=>assert.equal(api.scan({customName:'가상값'},['custom_name']).hits.filter(f=>f.type==='custom').length,1));
for(const value of ['010-0000-0000','+82-10-0000-0000','821000000000','+82 (0)10 0000 0000','0082-10-0000-0000','070-0000-0000','02-000-0000'])test('phone '+value,()=>assert.equal(found({phone:value},'phone').length,1));
test('updatePhone not suppressed by date substring',()=>assert.equal(found({updatePhone:'010-0000-0000'},'phone').length,1));
test('timestamp still has metadata suppression',()=>assert.equal(found({timestamp:'010-0000-0000'},'phone').length,0));
const cards=[['Visa16','4111111111111111'],['Visa13','4222222222222'],['Mastercard2','2223003122003222'],['Amex-contiguous','378282246310005'],['Amex-grouped','3782 822463 10005'],['Diners','30569309025904']];
for(const [brand,value] of cards)test('payment test PAN '+brand,()=>{const hits=found({cardNo:value},'card');assert.equal(hits.length,1);assert.equal(hits[0].verified,true);});
test('unknown issuer in card field remains unverified candidate',()=>{const hits=found({cardNo:'9000000000000000'},'card');assert.equal(hits.length,1);assert.equal(hits[0].tier,'candidate');assert.notEqual(hits[0].verified,true);});
for(const [key,value,type] of [['bank_account_no','000-000000-00-000','bank'],['passportNo','M00000000','passport'],['passport_no','M000A0000','passport'],['driver_license_no','00-00-000000-00','license']])test('dedicated-key heuristic '+type+' '+key,()=>{const hits=found({[key]:value},type);assert.equal(hits.length,1);assert.equal(hits[0].tier,'candidate');assert.notEqual(hits[0].verified,true);});
test('unknown field does not turn account shape into bank finding',()=>assert.equal(found({reference:'000-000000-00-000'},'bank').length,0));
test('malformed dedicated-key candidates rejected',()=>{for(const type of ['bank','passport','license'])assert.equal(api.scan({bankAccountNo:'not-a-number',passportNo:'invalid',driverLicenseNo:'invalid'}).hits.filter(f=>f.type===type).length,0);});
test('exactly 50000 matches has no truncation warning',()=>{const r=api.matches('x@example.test '.repeat(50000));assert.equal(r.hits.length,50000);assert.equal(r.diagnostics.length,0);});
test('50002 matches records explicit partial-analysis warning',()=>{const r=api.matches('x@example.test '.repeat(50002));assert.equal(r.hits.length,50000);assert.equal(r.diagnostics.length,1);assert.match(r.diagnostics[0].reason,/일부 미분석/);});
console.log(passed+' detection regression checks passed.');
