// Pure disk-image engine. The same functions run in the worker and in Node tests.
export const BLOCK_SIZE = 4096;
export const MAX_IMAGE_SIZE = 128 * 1024 * 1024;
const enc = new TextEncoder();
export const hex = bytes => Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
export const sha256 = async bytes => hex(await crypto.subtle.digest('SHA-256', bytes));
export const canonical = value => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
};
export async function digestObject(obj) { return sha256(enc.encode(canonical(obj))); }
export function findBytes(bytes, needle, from = 0, limit = bytes.length) {
  outer: for (let i = from; i <= limit - needle.length; i++) {
    if (bytes[i] !== needle[0]) continue;
    for (let j = 1; j < needle.length; j++) if (bytes[i+j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}
const u32 = (b, o) => o + 4 <= b.length ? new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(o, false) : 0;
const le16 = (b, o) => o + 2 <= b.length ? b[o] | b[o+1] << 8 : 0;
export function crc32(bytes) {
  let crc = 0xffffffff;
  for (const b of bytes) { crc ^= b; for (let k=0;k<8;k++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1)); }
  return (crc ^ 0xffffffff) >>> 0;
}

// Contiguous carving only. Confidence describes structure, never provenance.
export function carve(bytes, report = () => {}) {
  const files = [];
  const png = new Uint8Array([137,80,78,71,13,10,26,10]);
  const pdf = enc.encode('%PDF-'); const eof = enc.encode('%%EOF');
  let lastReport = 0;
  for (let i=0; i<bytes.length-3; i++) {
    if (i-lastReport > 524288) { lastReport=i;report(i/bytes.length); }
    const start=i; let end=0, type='', checks=[], confidence=0;
    if (bytes[i]===137 && findBytes(bytes,png,i,i+8)===i) {
      let p=i+8, count=0, valid=true, first=true;
      while (p+12<=bytes.length && count++<10000) {
        const len=u32(bytes,p); if (len>16*1024*1024 || p+12+len>bytes.length) { valid=false; break; }
        const name=String.fromCharCode(...bytes.subarray(p+4,p+8));
        if (first && (name!=='IHDR' || len!==13)) { valid=false; break; }
        first=false;
        if (crc32(bytes.subarray(p+4,p+8+len))!==u32(bytes,p+8+len)) valid=false;
        p+=12+len;
        if (name==='IEND') { if(len===0)end=p; break; }
      }
      if (end) { type='PNG';confidence=valid?99:55;checks=valid?['Header matched','Chunk boundaries valid','All chunk CRCs valid','IEND present']:['Header matched','IEND present','CRC or structure mismatch']; }
    } else if (bytes[i]===37 && findBytes(bytes,pdf,i,i+5)===i) {
      const p=findBytes(bytes,eof,i+5,Math.min(bytes.length,i+16*1024*1024));
      if (p>=0) { end=p+eof.length;while(end<bytes.length&&(bytes[end]===10||bytes[end]===13))end++; type='PDF';confidence=75;checks=['Header matched','End marker present','Contiguous candidate; object graph not validated']; }
    } else if (bytes[i]===255 && bytes[i+1]===216 && bytes[i+2]===255) {
      const p=findBytes(bytes,new Uint8Array([255,217]),i+3,Math.min(bytes.length,i+16*1024*1024));
      if(p>=0){end=p+2;type='JPEG';confidence=60;checks=['SOI matched','EOI present','Contiguous candidate; image decode not validated'];}
    } else if (bytes[i]===80 && bytes[i+1]===75 && bytes[i+2]===3 && bytes[i+3]===4) {
      const sig=new Uint8Array([80,75,5,6]);
      let p=findBytes(bytes,sig,i+4,Math.min(bytes.length,i+32*1024*1024));
      while(p>=0 && p+22<=bytes.length){
        const comment=le16(bytes,p+20);
        if(p+22+comment<=bytes.length){end=p+22+comment;break;}
        p=findBytes(bytes,sig,p+4,Math.min(bytes.length,i+32*1024*1024));
      }
      if(end){type='ZIP';confidence=65;checks=['Local header matched','End-of-central-directory present','Contiguous candidate; archive contents not validated'];}
    }
    if(end>start){files.push({id:`carve-${start}`,type,offset:start,length:end-start,confidence,checks});i=end-1;}
  }
  report(1); return files;
}

export async function fingerprint(bytes, targets) {
  const manifest=[];
  for (const target of targets) {
    const blocks=[];
    for(let offset=Math.floor(target.start/BLOCK_SIZE)*BLOCK_SIZE;offset<target.start+target.length;offset+=BLOCK_SIZE)
      blocks.push({offset,hash:await sha256(bytes.subarray(offset,Math.min(bytes.length,offset+BLOCK_SIZE)))});
    manifest.push({...target,hash:await sha256(bytes.subarray(target.start,target.start+target.length)),blocks});
  }
  return manifest;
}

export async function verify(bytes, manifest=[], report=()=>{}) {
  const files=carve(bytes,p=>report(p*.5));
  let nonzero=0;for(let i=0;i<bytes.length;i++)if(bytes[i]!==0)nonzero++;
  const references=new Set(manifest.flatMap(f=>f.blocks.map(b=>b.hash)));
  const recovered=new Set();
  // Scan every aligned host-visible block, including moved copies.
  if(references.size)for(let offset=0;offset<bytes.length;offset+=BLOCK_SIZE){
    let active=false;const block=bytes.subarray(offset,Math.min(bytes.length,offset+BLOCK_SIZE));
    for(const b of block)if(b){active=true;break;}
    if(active){const hash=await sha256(block);if(references.has(hash))recovered.add(hash);}
    if(offset%524288===0)report(.5+.45*offset/bytes.length);
  }
  const names=manifest.filter(f=>findBytes(bytes,enc.encode(f.name))>=0).map(f=>f.name);
  const denominator=references.size+manifest.length;
  const rrs=denominator?(recovered.size+names.length)/denominator:null;
  report(1);
  return {rrs,targetBlockCount:references.size,recoveredBlocks:recovered.size,metadataMatches:names,nonzeroBytes:nonzero,carvedFiles:files,bytesChecked:bytes.length,readbackPassed:nonzero===0,passed:nonzero===0&&files.length===0&&recovered.size===0&&names.length===0,sha256:await sha256(bytes),scope:'Complete host-visible image bytes; no physical media, firmware, snapshots, or hidden areas.'};
}

const fromBase64 = b64 => Uint8Array.from(atob(b64), c=>c.charCodeAt(0));
function fixturePng() {
  // One RGBA pixel; chunk CRCs are generated rather than assumed.
  const chunk=(name,data)=>{const b=new Uint8Array(data.length+12);const v=new DataView(b.buffer);v.setUint32(0,data.length);b.set(enc.encode(name),4);b.set(data,8);v.setUint32(8+data.length,crc32(b.subarray(4,8+data.length)));return b;};
  const hdr=new Uint8Array(13);new DataView(hdr.buffer).setUint32(0,1);new DataView(hdr.buffer).setUint32(4,1);hdr[8]=8;hdr[9]=6;
  const chunks=[new Uint8Array([137,80,78,71,13,10,26,10]),chunk('IHDR',hdr),chunk('IDAT',fromBase64('eJxjMMp0+w8AA5MB4Q==')),chunk('IEND',new Uint8Array())];
  const out=new Uint8Array(chunks.reduce((n,c)=>n+c.length,0));let p=0;for(const c of chunks){out.set(c,p);p+=c.length;}return out;
}
function fixturePdf(){
  const stream='BT /F1 18 Tf 40 100 Td (EraseProof research fixture) Tj ET';
  const objects=['<< /Type /Catalog /Pages 2 0 R >>','<< /Type /Pages /Kids [3 0 R] /Count 1 >>','<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 160] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>','<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`];
  let text='%PDF-1.4\n', offsets=[0];objects.forEach((o,i)=>{offsets.push(text.length);text+=`${i+1} 0 obj\n${o}\nendobj\n`;});const xref=text.length;text+=`xref\n0 6\n0000000000 65535 f \n`+offsets.slice(1).map(n=>`${String(n).padStart(10,'0')} 00000 n \n`).join('')+`trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;return enc.encode(text);
}
export async function createFixture(kind=0){
  const sizes=[8,4,2], names=['Research workstation','Transfer archive','Field collection'];
  const bytes=new Uint8Array(sizes[kind]*1024*1024);
  const png=fixturePng(),pdf=fixturePdf();
  const records=[{name:'research-notes.pdf',start:65536,data:pdf,type:'PDF'},{name:'capture-original.png',start:262144,data:png,type:'PNG'},{name:'research-notes.previous.pdf',start:524288,data:pdf,type:'PDF'},{name:'capture-backup.png',start:786432,data:png,type:'PNG'}];
  for(const r of records)bytes.set(r.data,r.start);
  bytes.set(enc.encode(records.map(r=>r.name).join('\n')),16384);
  const manifest=await fingerprint(bytes,records.map(({data,...r})=>({...r,length:data.length})));
  return {id:crypto.randomUUID(),name:names[kind],filename:['workstation-lab.img','transfer-lab.img','field-lab.img'][kind],size:bytes.length,source:'fixture',created:new Date().toISOString(),status:'ready',manifest,buffer:bytes.buffer};
}
