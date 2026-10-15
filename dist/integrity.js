import { canonical, digestObject } from './core.js';
const enc=new TextEncoder();
const encode=bytes=>{let text='';for(const b of new Uint8Array(bytes))text+=String.fromCharCode(b);return btoa(text);};
const decode=text=>Uint8Array.from(atob(text),c=>c.charCodeAt(0));
export async function signRecord(payload,keys){
  const publicKey=await crypto.subtle.exportKey('jwk',keys.publicKey);
  const signature=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},keys.privateKey,enc.encode(canonical(payload)));
  return {payload,payloadSha256:await digestObject(payload),publicKey,signature:encode(signature)};
}
export async function verifyCertificate(record){
  if(!record||typeof record!=='object'||record.payload?.schema!=='eraseproof.image-record.v1'||record.payload.algorithm!=='ECDSA-P256-SHA256'||typeof record.signature!=='string'||record.signature.length>1024||!record.publicKey)throw new Error('This is not a supported EraseProof image record.');
  if(await digestObject(record.payload)!==record.payloadSha256)return false;
  const key=await crypto.subtle.importKey('jwk',record.publicKey,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  return crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,decode(record.signature),enc.encode(canonical(record.payload)));
}
export async function verifyAudit(entries){
  let previous='0'.repeat(64);
  for(let i=0;i<entries.length;i++){
    const {hash,...entry}=entries[i];
    if(entry.previousHash!==previous||entry.sequence!==i+1||await digestObject(entry)!==hash)return false;
    previous=hash;
  }
  return true;
}
