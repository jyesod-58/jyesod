/* IndexedDB payload helpers, inserted inside the detector IIFE by its build step.
 * No database is opened until an explicit store/hydrate call. Raw data is local,
 * plaintext browser storage: the UI must disclose retention and offer deletion.
 */
const PAYLOAD_DB_NAME='pii-review-payloads-v2.1';
const PAYLOAD_STORE_NAME='payloads';
const PAYLOAD_FIELDS=Object.freeze(['text','rawResponseBase64','originalResponseBase64','request','harBodyBase64','harHead','originalHeaders']);
const PAYLOAD_SESSION_ID=globalThis.crypto?.randomUUID?.()||('session-'+Date.now().toString(36)+'-'+Math.random().toString(36).slice(2));
const PAYLOAD_SESSION_PREFIX=PAYLOAD_SESSION_ID+':';
let payloadDatabasePromise=null,payloadDatabase=null,payloadStoreUsed=false;
let payloadOperationTail=Promise.resolve(),payloadEpoch=0,payloadSequence=0;
class PayloadStorageError extends Error {
  constructor(message,code='storage'){super(message);this.name='PayloadStorageError';this.code=code;}
}
function payloadError(error,operation){
  if(error instanceof PayloadStorageError)return error;
  if(error?.name==='QuotaExceededError')return new PayloadStorageError('브라우저 임시저장 공간이 부족합니다. 파일을 나누거나 불필요한 사이트 저장 데이터를 지운 뒤 다시 시도하세요.','quota');
  if(error?.name==='SecurityError'||error?.name==='InvalidStateError'||error?.name==='NotAllowedError')return new PayloadStorageError('브라우저 정책 또는 개인정보 보호 설정 때문에 임시저장소를 사용할 수 없습니다. 이 사이트의 IndexedDB 허용 여부를 확인하세요.','permission');
  if(error?.name==='AbortError')return new PayloadStorageError('임시저장 작업이 중단되었습니다. 브라우저 저장 공간과 페이지 상태를 확인한 뒤 다시 불러오세요.','abort');
  return new PayloadStorageError('브라우저 임시저장소 '+operation+' 작업에 실패했습니다. 원문은 오류 메시지에 포함하지 않았습니다. 파일을 나누거나 다른 지원 브라우저에서 다시 시도하세요.','storage');
}
function payloadCancellation(){return new PayloadStorageError('이전 임시저장 작업이 취소되었습니다. 현재 파일 불러오기 상태를 확인하세요.','cancelled');}
function queuePayloadOperation(operation){
  const task=payloadOperationTail.then(operation,operation);
  // Never retain the last hydrated response as a resolved queue value.
  payloadOperationTail=task.then(()=>undefined,()=>undefined);
  return task;
}
function openPayloadDatabase(){
  if(payloadDatabasePromise)return payloadDatabasePromise;
  payloadDatabasePromise=new Promise((resolve,reject)=>{
    if(!globalThis.indexedDB){reject(new PayloadStorageError('이 브라우저는 IndexedDB 임시저장을 지원하지 않습니다. 대용량 모드를 사용할 수 없습니다.','unsupported'));return;}
    let request,settled=false;
    const fail=error=>{if(!settled){settled=true;reject(payloadError(error,'열기'));}};
    try{request=indexedDB.open(PAYLOAD_DB_NAME,1);}catch(error){fail(error);return;}
    request.onupgradeneeded=()=>{
      const database=request.result;
      if(!database.objectStoreNames.contains(PAYLOAD_STORE_NAME))database.createObjectStore(PAYLOAD_STORE_NAME,{keyPath:'key'});
    };
    request.onerror=()=>fail(request.error);
    request.onblocked=()=>fail(new PayloadStorageError('다른 탭이 이전 임시저장소를 사용하고 있습니다. 관련 탭을 닫은 뒤 다시 시도하세요.','blocked'));
    request.onsuccess=()=>{
      const database=request.result;if(settled){database.close();return;}
      settled=true;payloadDatabase=database;
      database.onversionchange=()=>{database.close();if(payloadDatabase===database){payloadDatabase=null;payloadDatabasePromise=null;}};
      database.onclose=()=>{if(payloadDatabase===database){payloadDatabase=null;payloadDatabasePromise=null;}};
      resolve(database);
    };
  }).catch(error=>{payloadDatabasePromise=null;throw payloadError(error,'열기');});
  return payloadDatabasePromise;
}
function payloadTransaction(database,mode,action){
  return new Promise((resolve,reject)=>{
    let transaction,result;
    try{
      transaction=database.transaction(PAYLOAD_STORE_NAME,mode);
      transaction.oncomplete=()=>resolve(result);
      transaction.onerror=()=>{}; // onabort reports the transaction's definitive failure.
      transaction.onabort=()=>reject(payloadError(transaction.error,'저장/읽기'));
      action(transaction.objectStore(PAYLOAD_STORE_NAME),value=>{result=value;},transaction);
    }catch(error){
      try{transaction?.abort();}catch{}
      reject(payloadError(error,'저장/읽기'));
    }
  });
}
async function storePagePayload(pg){
  if(!pg||typeof pg!=='object')throw new PayloadStorageError('임시저장할 응답 항목이 올바르지 않습니다.','input');
  const epoch=payloadEpoch;payloadStoreUsed=true;
  return queuePayloadOperation(async()=>{
    if(epoch!==payloadEpoch)throw payloadCancellation();
    const present=PAYLOAD_FIELDS.filter(field=>Object.hasOwn(pg,field));
    if(!present.length)return pg;
    const database=await openPayloadDatabase();if(epoch!==payloadEpoch)throw payloadCancellation();
    const key=typeof pg.payloadKey==='string'&&pg.payloadKey.startsWith(PAYLOAD_SESSION_PREFIX)?pg.payloadKey:PAYLOAD_SESSION_PREFIX+(++payloadSequence);
    const payload={};for(const field of present)payload[field]=pg[field];
    const textLength=typeof pg.text==='string'?pg.text.length:Number(pg.textLength)||0;
    const hasResponse=!!(pg.hasResponse||pg.text||pg.rawResponseBase64!=null||pg.originalResponseBase64!=null||pg.harBodyBase64!=null);
    try{
      await payloadTransaction(database,'readwrite',(store)=>{
        if(pg.payloadKey===key){
          const previous=store.get(key);previous.onsuccess=()=>{
            const retained=previous.result?.session===PAYLOAD_SESSION_ID?previous.result.payload:{};
            store.put({key,session:PAYLOAD_SESSION_ID,payload:{...retained,...payload}});
          };
        }else store.put({key,session:PAYLOAD_SESSION_ID,payload});
      });
    }catch(error){throw payloadError(error,'저장');}
    if(epoch!==payloadEpoch)throw payloadCancellation();
    // Commit first. If quota/policy/write fails, original fields remain available.
    pg.payloadKey=key;pg.textLength=textLength;pg.hasResponse=hasResponse;
    for(const field of present)delete pg[field];
    return pg;
  });
}
async function hydratePage(pg){
  if(!pg||typeof pg!=='object')throw new PayloadStorageError('불러올 응답 항목이 올바르지 않습니다.','input');
  if(!pg.payloadKey)return {...pg};
  const epoch=payloadEpoch,key=pg.payloadKey;
  if(typeof key!=='string'||!key.startsWith(PAYLOAD_SESSION_PREFIX))throw new PayloadStorageError('이 응답은 현재 임시저장 세션에 속하지 않습니다. 원본 파일 또는 원문 포함 프로젝트를 다시 불러오세요.','session');
  payloadStoreUsed=true;
  return queuePayloadOperation(async()=>{
    if(epoch!==payloadEpoch)throw payloadCancellation();
    const database=await openPayloadDatabase();if(epoch!==payloadEpoch)throw payloadCancellation();
    const record=await payloadTransaction(database,'readonly',(store,set)=>{const request=store.get(key);request.onsuccess=()=>set(request.result);});
    if(epoch!==payloadEpoch)throw payloadCancellation();
    if(!record?.payload||record.session!==PAYLOAD_SESSION_ID)throw new PayloadStorageError('임시저장된 응답 원문을 찾지 못했습니다. 삭제 또는 저장 공간 회수 여부를 확인하고 원본 파일을 다시 불러오세요.','missing');
    // Metadata wins over stored fields only outside PAYLOAD_FIELDS. This is a new
    // object: callers can drop it after one scan/detail view without changing pg.
    const hydrated={...pg};for(const field of PAYLOAD_FIELDS)if(Object.hasOwn(record.payload,field))hydrated[field]=record.payload[field];
    return hydrated;
  });
}
async function clearPayloadStore(){
  // Invalidates already queued/in-flight readers and writers synchronously.
  ++payloadEpoch;
  return queuePayloadOperation(async()=>{
    if(!payloadStoreUsed&&!payloadDatabasePromise)return;
    const database=await openPayloadDatabase();
    await payloadTransaction(database,'readwrite',(store)=>{
      const range=IDBKeyRange.bound(PAYLOAD_SESSION_PREFIX,PAYLOAD_SESSION_PREFIX+'\uffff');
      store.delete(range);
    });
    // Preserve the live DB connection; the serialized queue prevents a close/open
    // race and fresh operations use the incremented epoch. Other tabs are separate.
  });
}
async function purgeAllPayloadStores(){
  // Explicit destructive action: removes this dedicated app database's payloads
  // across sessions, including abandoned rows from reloads/closed tabs. Other
  // tabs must be closed first; their references cannot survive this operation.
  ++payloadEpoch;
  return queuePayloadOperation(async()=>{
    const database=await openPayloadDatabase();
    await payloadTransaction(database,'readwrite',store=>{store.clear();});
  });
}
async function estimatePayloadStorage(){
  try{
    const estimate=globalThis.navigator?.storage?.estimate?await navigator.storage.estimate():{};
    const persistent=globalThis.navigator?.storage?.persisted?await navigator.storage.persisted():null;
    const usage=Number.isFinite(estimate.usage)?estimate.usage:null,quota=Number.isFinite(estimate.quota)?estimate.quota:null;
    return {available:!!globalThis.indexedDB,usageBytes:usage,quotaBytes:quota,availableBytes:usage!==null&&quota!==null?Math.max(0,quota-usage):null,persistent};
  }catch(error){throw payloadError(error,'용량 확인');}
}
async function requestPersistence(){
  // Only call from an explicit user action. Merely opening/importing never asks.
  if(!globalThis.navigator?.storage?.persist)return {supported:false,granted:false};
  try{return {supported:true,granted:await navigator.storage.persist()};}catch(error){throw payloadError(error,'보관 권한 요청');}
}
