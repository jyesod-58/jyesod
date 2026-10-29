/* Optional 500MiB synthetic streaming stress test. Never builds a whole-file buffer. */
const fs=require('fs'),path=require('path'),assert=require('assert'),crypto=require('crypto');
const src=fs.readFileSync(path.join(__dirname,'../burp_stream_fragment.js'),'utf8');
const {readBurpItems}=new Function(src+';return {readBurpItems}')();
const mebibytes=Number(process.argv[2]||500);
assert(Number.isSafeInteger(mebibytes)&&mebibytes>=1&&mebibytes<=2000);
const prefix=Buffer.from('<items>'),suffix=Buffer.from('</items>'),opening=Buffer.from('<item><response><![CDATA['),closing=Buffer.from(']]></response></item>');
const record=Buffer.concat([opening,Buffer.alloc(1024*1024-opening.length-closing.length,120),closing]);
const bodyLength=record.length*mebibytes,total=prefix.length+bodyLength+suffix.length;
let reads=0,maxRead=0,peakHeap=0,last;
const file={size:total,slice(a,b){
  assert(b-a<=1024*1024);reads++;maxRead=Math.max(maxRead,b-a);
  return {async arrayBuffer(){const output=Buffer.alloc(b-a);let position=a,written=0;while(position<b){let source,index;if(position<prefix.length){source=prefix;index=position;}else if(position<prefix.length+bodyLength){source=record;index=(position-prefix.length)%record.length;}else{source=suffix;index=position-prefix.length-bodyLength;}const count=Math.min(source.length-index,b-position);source.copy(output,written,index,index+count);written+=count;position+=count;}return output.buffer.slice(output.byteOffset,output.byteOffset+output.byteLength);}};
}};
(async()=>{const started=Date.now();let count=0;for await(const item of readBurpItems(file,{onProgress:p=>{last=p;peakHeap=Math.max(peakHeap,process.memoryUsage().heapUsed);}})){assert(!item.error);assert(item.text.startsWith('<item>'));assert(item.text.endsWith('</item>'));assert.equal(item.itemNumber,++count);}
const expected=crypto.createHash('sha256').update(prefix);for(let i=0;i<mebibytes;i++)expected.update(record);expected.update(suffix);
assert.equal(count,mebibytes);assert.equal(last.fullyRead,true);assert.equal(last.bytesRead,total);assert.equal(last.sha256,expected.digest('hex'));
console.log(JSON.stringify({passed:true,syntheticMiB:mebibytes,items:count,bytesRead:last.bytesRead,maxRead,reads,elapsedSeconds:(Date.now()-started)/1000,peakHeapMiB:Math.round(peakHeap/1024/1024)},null,2));
})().catch(error=>{console.error(error);process.exitCode=1;});
