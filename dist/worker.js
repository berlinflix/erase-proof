import { carve, verify, sha256 } from './core.js';
self.onmessage = async ({data}) => {
  const {kind,buffer,manifest=[]}=data;
  try {
    const bytes=new Uint8Array(buffer);
    const progress=(stage,value,message)=>self.postMessage({type:'progress',stage,value,message});
    if(kind==='scan'){
      progress('attack',0,'Searching every image byte for contiguous file signatures.');
      const files=carve(bytes,p=>progress('attack',p,`Scanning ${Math.round(p*100)}% of the image`));
      self.postMessage({type:'scan-complete',files,sha256:await sha256(bytes)});return;
    }
    if(kind==='verify'){
      const result=await verify(bytes,manifest,p=>progress('attack',p,'Checking image bytes, file signatures, fingerprints and names.'));
      self.postMessage({type:'verify-complete',result});return;
    }
    progress('discover',1,`Image boundary confirmed: ${bytes.length.toLocaleString()} bytes.`);
    const beforeHash=await sha256(bytes);
    progress('plan',1,'Full-image zero overwrite; complete read-back and recovery attack.');
    const chunk=262144;
    for(let offset=0;offset<bytes.length;offset+=chunk){bytes.fill(0,offset,Math.min(offset+chunk,bytes.length));progress('erase',Math.min(1,(offset+chunk)/bytes.length),'Overwriting the complete image, including embedded metadata and old versions.');}
    const result=await verify(bytes,manifest,p=>progress('attack',p,'Full read-back, signature carving and known-residue search.'));
    self.postMessage({type:'erase-complete',beforeHash,result,buffer:bytes.buffer},[bytes.buffer]);
  }catch(error){self.postMessage({type:'error',message:error.message||String(error)});}
};
