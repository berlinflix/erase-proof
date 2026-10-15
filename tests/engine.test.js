import test from 'node:test';
import assert from 'node:assert/strict';
import { inflateSync } from 'node:zlib';
import { createFixture, carve, verify, sha256, digestObject, BLOCK_SIZE } from '../dist/core.js';
import { signRecord, verifyCertificate, verifyAudit } from '../dist/integrity.js';

test('fixtures carve into two complete PDFs and two valid, decodable PNGs', async()=>{
  const image=await createFixture(2), bytes=new Uint8Array(image.buffer),files=carve(bytes);
  assert.equal(files.length,4);
  assert.deepEqual(files.map(f=>f.type),['PDF','PNG','PDF','PNG']);
  for(const file of files.filter(f=>f.type==='PNG')){
    assert.equal(file.confidence,99);
    const start=file.offset+8;let p=start;
    while(String.fromCharCode(...bytes.slice(p+4,p+8))!=='IDAT')p+=12+new DataView(bytes.buffer).getUint32(p);
    const len=new DataView(bytes.buffer).getUint32(p);
    assert.deepEqual([...inflateSync(bytes.slice(p+8,p+8+len))],[0,50,105,70,255]);
  }
});
test('un-erased fixture fails read-back and recovers its known content and filenames',async()=>{
  const image=await createFixture(2), result=await verify(new Uint8Array(image.buffer),image.manifest);
  assert.equal(result.passed,false);assert.equal(result.readbackPassed,false);
  assert.equal(result.rrs,1);assert.equal(result.carvedFiles.length,4);
  assert.equal(result.metadataMatches.length,4);assert.equal(result.recoveredBlocks,result.targetBlockCount);
});
test('overwriting every byte produces zero RRS and a reproducible output hash',async()=>{
  const image=await createFixture(2),bytes=new Uint8Array(image.buffer);bytes.fill(0);
  const result=await verify(bytes,image.manifest);
  assert.equal(result.passed,true);assert.equal(result.rrs,0);assert.equal(result.nonzeroBytes,0);
  assert.equal(result.carvedFiles.length,0);assert.equal(result.bytesChecked,image.size);
  assert.equal(result.sha256,await sha256(new Uint8Array(image.size)));
});
test('skipped metadata cleanup is detected even when all file payloads are gone',async()=>{
  const image=await createFixture(2),bytes=new Uint8Array(image.buffer);
  for(const f of image.manifest)bytes.fill(0,f.start,f.start+f.length);
  const result=await verify(bytes,image.manifest);
  assert.equal(result.passed,false);assert.equal(result.carvedFiles.length,0);
  assert.equal(result.recoveredBlocks,0);assert.equal(result.metadataMatches.length,4);assert.ok(result.rrs>0);
});
test('block matching detects a known payload moved to another aligned location',async()=>{
  const image=await createFixture(2),bytes=new Uint8Array(image.buffer);
  const block=bytes.slice(image.manifest[0].blocks[0].offset,image.manifest[0].blocks[0].offset+BLOCK_SIZE);
  bytes.fill(0);bytes.set(block,1024*1024);
  const result=await verify(bytes,image.manifest);
  assert.ok(result.recoveredBlocks>0);assert.ok(result.rrs>0);assert.equal(result.passed,false);
});
test('no reference set yields unavailable RRS; isolated residual bytes still fail verification',async()=>{
  const bytes=new Uint8Array(8192);bytes[8191]=1;
  const result=await verify(bytes,[]);
  assert.equal(result.rrs,null);assert.equal(result.nonzeroBytes,1);assert.equal(result.passed,false);
  bytes.fill(0);const clean=await verify(bytes,[]);assert.equal(clean.rrs,null);assert.equal(clean.passed,true);
});
test('carver rejects truncated PNG/PDF and does not crash on malformed lengths',()=>{
  const malformed=new Uint8Array([137,80,78,71,13,10,26,10,255,255,255,255,73,72,68,82]);
  assert.deepEqual(carve(malformed),[]);
  assert.deepEqual(carve(new TextEncoder().encode('%PDF-1.4 unfinished')),[]);
  assert.deepEqual(carve(new Uint8Array()),[]);
});
test('JPEG and ZIP boundary candidates are found without claiming full validation',()=>{
  const jpeg=new Uint8Array([255,216,255,224,0,2,255,217]);
  const jf=carve(jpeg);assert.equal(jf.length,1);assert.equal(jf[0].type,'JPEG');assert.equal(jf[0].length,8);assert.equal(jf[0].confidence,60);
  const zip=new Uint8Array(52);zip.set([80,75,3,4],0);zip.set([80,75,5,6],30);
  const zf=carve(zip);assert.equal(zf.length,1);assert.equal(zf[0].type,'ZIP');assert.equal(zf[0].length,52);assert.equal(zf[0].confidence,65);
  assert.deepEqual(carve(jpeg.slice(0,6)),[]);
});
test('signed records verify and reject changed payloads, hashes, and wrong public keys',async()=>{
  const keys=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
  assert.equal(keys.privateKey.extractable,false);
  const payload={schema:'eraseproof.image-record.v1',algorithm:'ECDSA-P256-SHA256',image:{name:'fixture'},verification:{passed:true}};
  const record=await signRecord(payload,keys);assert.equal(await verifyCertificate(record),true);
  const tampered=structuredClone(record);tampered.payload.verification.passed=false;assert.equal(await verifyCertificate(tampered),false);
  tampered.payloadSha256=await digestObject(tampered.payload);assert.equal(await verifyCertificate(tampered),false);
  const other=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
  const wrong={...record,publicKey:await crypto.subtle.exportKey('jwk',other.publicKey)};assert.equal(await verifyCertificate(wrong),false);
  await assert.rejects(()=>verifyCertificate({}),/not a supported/);
});
test('audit verification detects edits, omissions, and reordered entries',async()=>{
  const events=[];for(let i=0;i<3;i++){const item={sequence:i+1,event:'test',detail:{value:i},previousHash:events.at(-1)?.hash||'0'.repeat(64)};events.push({...item,hash:await digestObject(item)});}
  assert.equal(await verifyAudit(events),true);
  const edited=structuredClone(events);edited[1].detail.value=99;assert.equal(await verifyAudit(edited),false);
  assert.equal(await verifyAudit([events[0],events[2]]),false);
  assert.equal(await verifyAudit([events[1],events[0],events[2]]),false);
});
