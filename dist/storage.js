let connection;
export async function db(){
  if(connection)return connection;
  connection=await new Promise((resolve,reject)=>{const req=indexedDB.open('eraseproof-workspace',1);req.onupgradeneeded=()=>{req.result.createObjectStore('images',{keyPath:'id'});req.result.createObjectStore('state');};req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(req.error);});
  return connection;
}
export async function readAllImages(){const d=await db();return new Promise((res,rej)=>{const r=d.transaction('images').objectStore('images').getAll();r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error);});}
export async function readState(key){const d=await db();return new Promise((res,rej)=>{const r=d.transaction('state').objectStore('state').get(key);r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error);});}
// Image bytes, evidence and audit history commit atomically.
export async function commit({images=[],remove=[],values={}}){
  const d=await db();return new Promise((resolve,reject)=>{
    const tx=d.transaction(['images','state'],'readwrite');let conflict=false;
    const write=()=>{for(const image of images)tx.objectStore('images').put(image);for(const id of remove)tx.objectStore('images').delete(id);for(const [k,v]of Object.entries(values))tx.objectStore('state').put(v,k);};
    if(values.audit){
      const req=tx.objectStore('state').get('audit');
      req.onsuccess=()=>{const prior=req.result||[],next=values.audit,entry=next.at(-1);if(next.length!==prior.length+1||entry?.previousHash!==(prior.at(-1)?.hash||'0'.repeat(64))){conflict=true;tx.abort();return;}write();};
    }else write();
    tx.oncomplete=()=>resolve();tx.onerror=()=>reject(tx.error);tx.onabort=()=>reject(conflict?new Error('Workspace changed in another tab. Reload to use the latest history.'):tx.error||new Error('Workspace transaction aborted'));
  });
}
