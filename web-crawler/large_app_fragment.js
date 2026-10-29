/* Large-file integration. All raw bytes remain on the local device. */
async function enableLargeMode(){
  if(S.largeMode)return;
  if(!confirm('대용량 파일은 원문을 이 브라우저의 평문 임시 저장소(IndexedDB)에 보관합니다. 탭을 닫거나 새로고침해도 남을 수 있습니다. 승인된 PC에서 사용하고 검토 후 임시 원문 전체 삭제를 실행하세요. 계속할까요?'))throw new Error('대용량 임시 저장을 취소했습니다.');
  await openPayloadDatabase();S.largeMode=true;S.operatorInference=false;$('#operatorChk').checked=false;
  for(const pg of S.pages)if(!pg.payloadKey)await storePagePayload(pg);
}
async function importLargeBurpFile(file,generation){
  await enableLargeMode();const pages=[],sourceId=++S.sourceSequence;let metadata={},error='';
  try{
    for await(const item of readBurpItems(file,{isCancelled:()=>generation!==loadGeneration,onProgress:m=>{
      metadata=m;setFileStatus(`${file.name} · ${Math.floor(m.bytesRead/m.totalBytes*100)}% 읽음 · ${m.itemNumber}개 거래 · 1MiB 단위 처리`);
    }})){
      if(generation!==loadGeneration)throw new Error('파일 가져오기를 취소했습니다.');
      if(S.pages.length+pages.length>=LIMITS.items)throw new Error('거래 250,000건 한도 도달: 나머지 파일은 미분석입니다.');
      let pg;
      try{if(item.error)throw new Error(item.error);pg=toPages('<items>'+item.text+'</items>',file.name)[0];if(!pg)throw new Error('응답 항목을 읽지 못했습니다.');}
      catch(e){pg={url:'(읽지 못한 항목)',text:'',importError:'항목 파싱 실패: '+e.message,prepared:true,preparationState:'failed'};}
      Object.assign(pg,{fileName:file.name,fileItem:item.itemNumber,sourceId,sourceHash:null});
      await preparePage(pg);pg.analysisHash=await sha256bytes(new TextEncoder().encode(pg.text||''));
      await storePagePayload(pg);pages.push(pg);
    }
    if(!pages.length)throw new Error('Burp XML에 항목이 없습니다.');
  }catch(e){if(generation!==loadGeneration)throw e;error=e.message;}
  const fullyRead=metadata.fullyRead===true&&!error,hash=fullyRead?metadata.sha256:null;
  for(const pg of pages){pg.sourceHash=hash;pg.sourceComplete=fullyRead;}
  S.sources.push({name:file.name,bytes:file.size,sha256:hash,fullyRead,items:pages.length});
  if(!pages.length&&error)throw new Error(error);return {pages,error,fullyRead};
}
function downloadLocalBlob(filename,blob){
  const url=URL.createObjectURL(blob),a=el('a');a.href=url;a.download=filename;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),60000);
}
async function largeProjectBlob(){
  const generation=loadGeneration,parts=[];
  const append=obj=>parts.push(new Blob([JSON.stringify(obj)+'\n'],{type:'application/x-ndjson'}));
  append({record:'header',kind:'public-agency-pii-review-stream-project',version:1,toolVersion:TOOL_VERSION,settings:currentProjectSettings(),sources:S.sources,fileCount:S.fileCount,sourceSequence:S.sourceSequence,importFailures:S.importFailures});
  for(let i=0;i<S.pages.length;i++){
    if(generation!==loadGeneration)throw new Error('프로젝트 저장을 취소했습니다.');
    const full=await hydratePage(S.pages[i]);delete full.payloadKey;delete full.textLength;delete full.hasResponse;
    append({record:'page',page:full});if(i%20===0){scanStatus(`프로젝트 저장 준비 ${i+1}/${S.pages.length}`);await yieldUI();}
  }
  for(const [key,value] of S.reviews)append({record:'review',key,value});
  append({record:'end',pages:S.pages.length,reviews:S.reviews.size});
  return new Blob(parts,{type:'application/x-ndjson'});
}
async function downloadLargeProject(){
  try{const blob=await largeProjectBlob();downloadLocalBlob('pii-review-project.jsonl',blob);}finally{scanStatus('');}
}
async function* readProjectLines(file){
  const decoder=new TextDecoder('utf-8',{fatal:true});let rest='';
  for(let offset=0;offset<file.size;offset+=1024*1024){
    rest+=decoder.decode(await file.slice(offset,offset+1024*1024).arrayBuffer(),{stream:true});let pos;
    while((pos=rest.indexOf('\n'))>=0){const line=rest.slice(0,pos);rest=rest.slice(pos+1);if(line.trim())yield line;}
    if(rest.length>40*1024*1024)throw new Error('프로젝트의 한 항목이 40Mi 문자 제한을 초과했습니다.');await yieldUI();
  }
  rest+=decoder.decode();if(rest.trim())yield rest;
}
async function restoreLargeProjectFile(file){
  if(reading||analysisBusy||preparing)throw new Error('진행 중인 처리가 끝난 후 불러오세요.');
  if(file.size>2*1024*1024*1024)throw new Error('대용량 프로젝트 한도 2GiB 초과입니다.');
  if(!confirm('대용량 프로젝트로 현재 분석과 판정을 교체합니다. 저장하지 않은 데이터는 지워집니다. 계속할까요?'))return;
  // Validate the header before replacing the current project.
  const iterator=readProjectLines(file),first=await iterator.next();let header;
  try{header=JSON.parse(first.value);}catch{throw new Error('프로젝트 헤더 JSON이 올바르지 않습니다.');}
  if(header.kind!=='public-agency-pii-review-stream-project'||header.version!==1||header.record!=='header')throw new Error('지원하는 대용량 프로젝트가 아닙니다.');
  goHome();await clearPayloadStore();await enableLargeMode();reading=true;const generation=loadGeneration,pages=[],reviews=new Map();let end=null;
  try{
    for await(const line of iterator){
      if(generation!==loadGeneration)throw new Error('복원을 취소했습니다.');const row=JSON.parse(line);if(end)throw new Error('종료 기록 뒤에 데이터가 있습니다.');
      if(row.record==='page'){
        const pg=row.page;if(!pg||typeof pg.url!=='string'||typeof pg.text!=='string')throw new Error('올바르지 않은 프로젝트 응답입니다.');
        if(pages.length>=LIMITS.items)throw new Error('프로젝트 거래 250,000건 제한입니다.');
        delete pg.payloadKey;delete pg.prepared;delete pg.analysis;delete pg.importError;delete pg.preparationState;delete pg.responseHash;delete pg.analysisHash;
        await preparePage(pg);pg.analysisHash=await sha256bytes(new TextEncoder().encode(pg.text||''));await storePagePayload(pg);pages.push(pg);
      }else if(row.record==='review'){
        if(typeof row.key!=='string'||!['true','false','pending'].includes(row.value))throw new Error('올바르지 않은 판정 기록입니다.');reviews.set(row.key,row.value);
      }else if(row.record==='end')end=row;else throw new Error('알 수 없는 프로젝트 기록입니다.');
    }
    if(!end||end.pages!==pages.length||end.reviews!==reviews.size)throw new Error('프로젝트가 잘렸거나 개수가 일치하지 않습니다.');
    await loadPages(pages,false,Math.max(0,Number(header.fileCount)||0));restoreProjectSettings(header.settings);S.operatorInference=false;$('#operatorChk').checked=false;
    S.sources=Array.isArray(header.sources)?header.sources:[];S.sourceSequence=Math.max(0,Number(header.sourceSequence)||0);S.importFailures=Array.isArray(header.importFailures)?header.importFailures:[];
    await rescan();S.reviews=reviews;refreshResults();setFileStatus(`대용량 프로젝트 복원 완료 · ${pages.length}개 거래`);
  }catch(e){if(generation===loadGeneration){S.importFailures.push({reason:'프로젝트 복원 중단: '+e.message});renderCoverage();}throw e;}
  finally{reading=false;}
}
$('#purgePayloads').addEventListener('click',async()=>{
  if(reading||analysisBusy||preparing){showToast('진행 중인 처리를 먼저 중지하세요.');return;}
  if(!confirm('현재 프로젝트를 비우고 이 브라우저의 이전 세션을 포함한 임시 원문을 모두 삭제합니다. 다른 검토 탭을 먼저 닫으세요. 필요한 프로젝트를 저장했나요?'))return;
  goHome();try{await purgeAllPayloadStores();setFileStatus('브라우저 임시 원문 전체 삭제 완료');}catch(e){setFileStatus('임시 원문 삭제 실패: '+e.message);}
});
