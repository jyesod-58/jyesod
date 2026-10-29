/* Offline streaming-input tests. Uses synthetic data only. Run with node. */
const fs=require('fs'),path=require('path'),assert=require('assert'),crypto=require('crypto');
const fragment=fs.readFileSync(path.join(__dirname,'../burp_stream_fragment.js'),'utf8');
const {SHA256Incremental,BurpXMLItemTokenizer,readBurpItems}=new Function(fragment+';return {SHA256Incremental,BurpXMLItemTokenizer,readBurpItems};')();
let tests=0;
function check(name,fn){fn();tests++;console.log('PASS '+name);}
async function checkAsync(name,fn){await fn();tests++;console.log('PASS '+name);}
function parse(text,step=3,options={}){const parser=new BurpXMLItemTokenizer(options),items=[];for(let i=0;i<text.length;i+=step)items.push(...parser.feed(text.slice(i,i+step)));const result=parser.finish();return {items,result};}
async function read(bytes,options={}){const blob=new Blob([bytes]),progress=[];const file={size:blob.size,slice(a,b){assert(b-a<=1024*1024,'whole-file buffer forbidden');return blob.slice(a,b);}};const items=[];for await(const it of readBurpItems(file,{...options,onProgress:metadata=>{progress.push(metadata);if(options.onProgress)options.onProgress(metadata);}}))items.push(it);return {items,progress};}

(async()=>{
  for(const length of [0,1,3,55,56,63,64,65,1000,1024*1024])check('SHA256 incremental bytes='+length,()=>{
    const input=Buffer.alloc(length,37),hash=new SHA256Incremental();for(let i=0;i<input.length;i+=7)hash.update(input.subarray(i,i+7));const expected=crypto.createHash('sha256').update(input).digest('hex');assert.equal(hash.digest(),expected);assert.equal(hash.digest(),expected);assert.throws(()=>hash.update(new Uint8Array([1])));
  });
  const item='<item name="literal > and &quot;" other=\'x\'><response><![CDATA[HTTP/2 200\r\n\r\n{"value":"</item>","html":"<!-- <item> -->"}]]></response><!-- </item> --></item>';
  const prolog='<?xml version="1.0"?><!DOCTYPE items [<!ELEMENT items (item*)><!ELEMENT item ANY><!ATTLIST item test CDATA "[ > ]"><!-- [ ] > -->]>';
  const xml=prolog+'<items>'+item+'<item><response base64="true">YWJj</response></item></items>';
  for(const step of [1,2,3,7,64,4096])check('lexical split='+step,()=>{const {items,result}=parse(xml,step);assert.equal(items.length,2);assert.equal(items[0].text,item);assert.equal(items[1].itemNumber,2);assert.equal(result.fullyRead,true);});
  check('self-closing item',()=>assert.equal(parse('<items><item /></items>',1).items[0].text,'<item />'));
  check('oversized item isolated and next item retained',()=>{const {items}=parse('<items><item><response>'+('x'.repeat(1000))+'</response></item><item /></items>',7,{itemLimit:100});assert.equal(items.length,2);assert.match(items[0].error,/크기 제한/);assert.equal(items[1].text,'<item />');assert.equal(items[1].itemNumber,2);});
  for(const broken of ['<items><item>','<items><item><![CDATA[unfinished','<items><item><!-- unfinished','<items><item value="unfinished','<items><item></wrong></items>','<items></items><items/>','<!DOCTYPE items [<!ENTITY fake "unsafe">]><items/>'])check('incomplete/malformed XML rejected '+broken.slice(0,35),()=>{assert.throws(()=>parse(broken,1),e=>e.fullyRead===false);});
  check('tag limit explicit partial failure',()=>assert.throws(()=>parse('<items><item value="'+'x'.repeat(200)+'"/></items>',5,{tokenLimit:100}),e=>e.fullyRead===false&&/태그/.test(e.message)));
  await checkAsync('streamed UTF8 and final original-byte hash',async()=>{const bytes=Buffer.from(xml,'utf8'),{items,progress}=await read(bytes);assert.equal(items.length,2);assert.equal(progress.at(-1).sha256,crypto.createHash('sha256').update(bytes).digest('hex'));assert.equal(progress.at(-1).fullyRead,true);assert.equal(progress.at(-1).bytesRead,bytes.length);});
  await checkAsync('UTF8 multibyte character straddles 1MiB boundary',async()=>{const start='<items><item><response><![CDATA[',padding='x'.repeat(1024*1024-Buffer.byteLength(start)-1),text=start+padding+'가상회원'+']]></response></item></items>',{items,progress}=await read(Buffer.from(text));assert(items[0].text.includes('가상회원'));assert(progress.length>=3);assert.equal(progress.at(-1).fullyRead,true);});
  await checkAsync('UTF16 LE BOM',async()=>{const text='<?xml version="1.0" encoding="UTF-16"?><items><item><response>가상</response></item></items>',bytes=Buffer.concat([Buffer.from([255,254]),Buffer.from(text,'utf16le')]),{items,progress}=await read(bytes);assert(items[0].text.includes('가상'));assert.equal(progress.at(-1).charset,'utf-16le');});
  await checkAsync('UTF16 BE BOM',async()=>{const text='<items><item><response>가상</response></item></items>',body=Buffer.from(text,'utf16le');body.swap16();const {items,progress}=await read(Buffer.concat([Buffer.from([254,255]),body]));assert(items[0].text.includes('가상'));assert.equal(progress.at(-1).charset,'utf-16be');});
  await checkAsync('EUC-KR declaration',async()=>{const bytes=Buffer.concat([Buffer.from('<?xml version="1.0" encoding="EUC-KR"?><items><item><response>'),Buffer.from('b0a1bbf3','hex'),Buffer.from('</response></item></items>')]),{items,progress}=await read(bytes);assert(items[0].text.includes('가상'));assert.equal(progress.at(-1).charset,'euc-kr');});
  await checkAsync('cancel is explicit incomplete state',async()=>{await assert.rejects(()=>read(Buffer.from(xml),{isCancelled:()=>true}),e=>e.fullyRead===false&&/취소/.test(e.message));});
  await checkAsync('truncated stream never reports complete',async()=>{const progress=[];await assert.rejects(()=>read(Buffer.from(xml.slice(0,-8)),{onProgress:p=>progress.push(p)}),e=>e.fullyRead===false);assert(!progress.some(p=>p.complete));});
  await checkAsync('invalid UTF8 does not silently replace characters',async()=>{await assert.rejects(()=>read(Buffer.from([60,105,116,101,109,115,62,255])),e=>e.fullyRead===false);});
  console.log(tests+' streaming/hash checks passed.');
})().catch(error=>{console.error(error);process.exitCode=1;});
