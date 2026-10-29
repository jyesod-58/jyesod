/* Incremental Burp XML input. No network calls and no whole-file buffers. */
class SHA256Incremental {
  constructor(){this.h=new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);this.buffer=new Uint8Array(64);this.used=0;this.bytes=0;this.done=false;this.w=new Uint32Array(64);}
  update(input){
    if(this.done)throw new Error('SHA-256 already finalized');
    const data=input instanceof Uint8Array?input:new Uint8Array(input);this.bytes+=data.length;
    let i=0;
    if(this.used){const n=Math.min(64-this.used,data.length);this.buffer.set(data.subarray(0,n),this.used);this.used+=n;i=n;if(this.used===64){this.block(this.buffer,0);this.used=0;}}
    for(;i+64<=data.length;i+=64)this.block(data,i);
    if(i<data.length){this.buffer.set(data.subarray(i));this.used=data.length-i;}
    return this;
  }
  block(data,offset){
    const w=this.w,k=SHA256Incremental.K,r=(v,n)=>(v>>>n)|(v<<(32-n));
    for(let i=0;i<16;i++){const j=offset+i*4;w[i]=((data[j]<<24)|(data[j+1]<<16)|(data[j+2]<<8)|data[j+3])>>>0;}
    for(let i=16;i<64;i++){const a=w[i-15],b=w[i-2];w[i]=(w[i-16]+(r(a,7)^r(a,18)^(a>>>3))+w[i-7]+(r(b,17)^r(b,19)^(b>>>10)))>>>0;}
    let [a,b,c,d,e,f,g,h]=this.h;
    for(let i=0;i<64;i++){const t1=(h+(r(e,6)^r(e,11)^r(e,25))+((e&f)^(~e&g))+k[i]+w[i])>>>0,t2=((r(a,2)^r(a,13)^r(a,22))+((a&b)^(a&c)^(b&c)))>>>0;h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;}
    const values=[a,b,c,d,e,f,g,h];for(let i=0;i<8;i++)this.h[i]=(this.h[i]+values[i])>>>0;
  }
  digest(){
    if(!this.done){const n=this.used;this.buffer[n]=0x80;this.buffer.fill(0,n+1);if(n>=56){this.block(this.buffer,0);this.buffer.fill(0);}const hi=Math.floor(this.bytes/0x20000000),lo=(this.bytes*8)>>>0;for(let j=0;j<4;j++){this.buffer[56+j]=(hi>>>(24-j*8))&255;this.buffer[60+j]=(lo>>>(24-j*8))&255;}this.block(this.buffer,0);this.done=true;}
    return Array.from(this.h,v=>v.toString(16).padStart(8,'0')).join('');
  }
}
SHA256Incremental.K=new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);

class BurpXMLItemTokenizer {
  constructor({itemLimit=32*1024*1024,tokenLimit=1024*1024}={}){this.itemLimit=itemLimit;this.tokenLimit=tokenLimit;this.stack=[];this.mode='data';this.token='';this.quote='';this.brackets=0;this.dtdComment=false;this.tail='';this.capture=null;this.itemNumber=0;this.rootSeen=false;this.rootClosed=false;this.dtdSeen=false;this.encoder=new TextEncoder();}
  fail(message){const error=new Error(message);error.fullyRead=false;error.itemNumber=this.itemNumber;throw error;}
  append(value){
    const c=this.capture;if(!c||c.oversized||!value)return;
    c.bytes+=this.encoder.encode(value).byteLength;
    if(c.bytes>this.itemLimit){c.oversized=true;c.parts=[];return;}
    c.parts.push(value);if(c.parts.length>=256)c.parts=[c.parts.join('')];
  }
  finishItem(out){const c=this.capture;this.capture=null;out.push(c.oversized?{error:'항목 XML 크기 제한(32MiB): 일부 미분석',itemNumber:this.itemNumber}:{text:c.parts.join(''),itemNumber:this.itemNumber});}
  tag(raw,out){
    const close=/^<\/([A-Za-z_:][A-Za-z0-9_.:-]*)\s*>$/.exec(raw);
    if(close){const name=close[1];if(this.stack.at(-1)!==name)this.fail('XML 종료 태그 불일치');this.append(raw);if(this.stack.length===2&&name==='item')this.finishItem(out);this.stack.pop();if(!this.stack.length)this.rootClosed=true;return;}
    const start=/^<([A-Za-z_:][A-Za-z0-9_.:-]*)/.exec(raw);if(!start)this.fail('잘못된 XML 시작 태그');
    const name=start[1],selfClosing=/\/>$/.test(raw),end=raw.length-(selfClosing?2:1);let pos=start[0].length;const attrs=new Set();
    while(pos<end){const ws=/^\s+/.exec(raw.slice(pos,end));if(!ws)this.fail('XML 속성 구분 오류');pos+=ws[0].length;if(pos===end)break;const attr=/^([A-Za-z_:][A-Za-z0-9_.:-]*)\s*=\s*(["'])([\s\S]*?)\2/.exec(raw.slice(pos,end));if(!attr||attr[3].includes('<')||attrs.has(attr[1]))this.fail('잘못된 XML 속성');attrs.add(attr[1]);pos+=attr[0].length;}
    if(!this.stack.length){if(this.rootSeen||this.rootClosed||name!=='items')this.fail('Burp items 루트가 필요합니다');this.rootSeen=true;}
    else if(this.stack.length===1){if(name!=='item')this.fail('items 루트의 직계 요소는 item이어야 합니다');this.itemNumber++;this.capture={parts:[],bytes:0,oversized:false};}
    this.append(raw);if(!selfClosing){this.stack.push(name);if(this.stack.length>256)this.fail('XML 중첩 깊이 제한(256)');}else if(this.capture&&this.stack.length===1)this.finishItem(out);else if(!this.stack.length)this.rootClosed=true;
  }
  feed(text){
    if(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(text))this.fail('XML에 허용되지 않는 제어 문자');
    const out=[];let i=0;
    while(i<text.length){
      if(this.mode==='data'){
        const end=text.indexOf('<',i),j=end<0?text.length:end,piece=text.slice(i,j);
        if(!this.capture&&piece.trim())this.fail('item 바깥의 XML 텍스트');this.append(piece);i=j;if(end<0)break;this.mode='markup';this.token='<';i++;continue;
      }
      if(this.mode==='comment'||this.mode==='cdata'){
        const old=this.tail.length,combined=this.tail+text.slice(i),marker=this.mode==='comment'?'-->':']]>',end=combined.indexOf(marker);
        if(end>=0){if(this.mode==='comment'&&combined.slice(0,end).includes('--'))this.fail('잘못된 XML 주석');this.append(combined.slice(0,end+3));i+=end+3-old;this.tail='';this.mode='data';continue;}
        if(this.mode==='comment'&&combined.slice(0,-2).includes('--'))this.fail('잘못된 XML 주석');const keep=Math.min(2,combined.length);this.append(combined.slice(0,combined.length-keep));this.tail=combined.slice(-keep);i=text.length;continue;
      }
      const ch=text[i++];this.token+=ch;
      if(this.token.length>this.tokenLimit)this.fail('XML 태그/선언 크기 제한(1MiB)');
      if(this.mode==='markup'){
        if(this.token==='<!--'){this.append(this.token);this.token='';this.mode='comment';this.tail='';continue;}
        if(this.token==='<![CDATA['){if(!this.capture)this.fail('item 바깥 CDATA');this.append(this.token);this.token='';this.mode='cdata';this.tail='';continue;}
        if(this.token==='<?'){this.mode='pi';continue;}
        if(this.token==='<!DOCTYPE'){if(this.rootSeen||this.dtdSeen)this.fail('DOCTYPE 위치 오류');this.mode='doctype';this.quote='';this.brackets=0;this.dtdComment=false;continue;}
        if(/^<\/?[A-Za-z_:]/.test(this.token)){this.mode='tag';this.quote='';}
        else if(['<!--','<![CDATA[','<!DOCTYPE','<?','</'].some(p=>p.startsWith(this.token)))continue;
        else this.fail('지원되지 않는 XML 선언 또는 태그');
      }
      if(this.mode==='tag'){
        if(this.quote){if(ch===this.quote)this.quote='';}
        else if(ch==='"'||ch==="'")this.quote=ch;
        else if(ch==='>'){this.tag(this.token,out);this.token='';this.mode='data';}
      }else if(this.mode==='pi'){
        if(this.token.endsWith('?>')){this.append(this.token);this.token='';this.mode='data';}
      }else if(this.mode==='doctype'){
        if(this.dtdComment){if(this.token.endsWith('-->'))this.dtdComment=false;continue;}
        if(this.quote){if(ch===this.quote)this.quote='';continue;}
        if(this.token.endsWith('<!--')){this.dtdComment=true;continue;}
        if(ch==='"'||ch==="'"){this.quote=ch;continue;}
        if(ch==='[')this.brackets++;else if(ch===']'){if(--this.brackets<0)this.fail('잘못된 DOCTYPE');}
        else if(ch==='>'&&this.brackets===0){if(!/^<!DOCTYPE\s+items(?:\s|>)/.test(this.token)||/<!ENTITY\b/.test(this.token))this.fail('사용자 정의 XML ENTITY는 지원하지 않습니다');this.dtdSeen=true;this.token='';this.mode='data';}
      }
    }
    return out;
  }
  finish(){if(this.mode!=='data'||this.stack.length||!this.rootSeen||!this.rootClosed||this.capture)this.fail('XML 파일이 끝나기 전에 잘렸거나 루트가 닫히지 않았습니다');return {fullyRead:true,itemNumber:this.itemNumber};}
}

async function* readBurpItems(file,{isCancelled=()=>false,onProgress=()=>{}}={}){
  const chunkSize=1024*1024,totalBytes=file.size,hash=new SHA256Incremental();let bytesRead=0,parser=new BurpXMLItemTokenizer();
  const fail=message=>{const error=new Error(message);error.fullyRead=false;error.bytesRead=bytesRead;error.totalBytes=totalBytes;error.itemNumber=parser.itemNumber;return error;};
  try{
    if(!Number.isSafeInteger(totalBytes)||totalBytes<1)throw fail('빈 XML 파일 또는 잘못된 파일 크기');
    const probe=new Uint8Array(await file.slice(0,Math.min(4096,totalBytes)).arrayBuffer());let charset='utf-8';
    if(probe[0]===0xff&&probe[1]===0xfe&&probe[2]===0&&probe[3]===0||probe[0]===0&&probe[1]===0&&probe[2]===0xfe&&probe[3]===0xff)throw fail('UTF-32 XML은 지원하지 않습니다');
    if(probe[0]===0xff&&probe[1]===0xfe||probe[0]===0x3c&&probe[1]===0)charset='utf-16le';
    else if(probe[0]===0xfe&&probe[1]===0xff||probe[0]===0&&probe[1]===0x3c)charset='utf-16be';
    else{const declaration=new TextDecoder('ascii').decode(probe).match(/^\s*(?:ï»¿)?<\?xml\b[^>]*encoding\s*=\s*["']([^"']+)["']/i);if(declaration){const label=declaration[1].toLowerCase();if(/^(?:euc-?kr|ks_c_5601-1987|cp949|windows-949)$/.test(label))charset='euc-kr';else if(!/^(?:utf-?8|us-ascii|ascii)$/.test(label))throw fail('지원되지 않는 XML 문자 인코딩');}}
    const decoder=new TextDecoder(charset,{fatal:true});
    for(let offset=0;offset<totalBytes;offset+=chunkSize){
      if(await isCancelled())throw fail('파일 읽기가 취소되었습니다');
      const chunk=new Uint8Array(await file.slice(offset,Math.min(offset+chunkSize,totalBytes)).arrayBuffer());if(!chunk.length)throw fail('파일 읽기가 예정보다 먼저 끝났습니다');hash.update(chunk);bytesRead+=chunk.length;
      const items=parser.feed(decoder.decode(chunk,{stream:true}));for(const item of items){if(await isCancelled())throw fail('파일 읽기가 취소되었습니다');yield item;}
      await onProgress({bytesRead,totalBytes,itemNumber:parser.itemNumber,fullyRead:false,complete:false,charset});
      await new Promise(resolve=>setTimeout(resolve,0));
    }
    for(const item of parser.feed(decoder.decode()))yield item;const metadata={...parser.finish(),bytesRead,totalBytes,complete:true,charset,sha256:hash.digest()};await onProgress(metadata);return metadata;
  }catch(error){error.fullyRead=false;error.bytesRead=bytesRead;error.totalBytes=totalBytes;error.itemNumber=parser.itemNumber;throw error;}
}
