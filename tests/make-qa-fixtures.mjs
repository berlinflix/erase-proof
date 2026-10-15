import { writeFile, mkdir, readFile } from 'node:fs/promises';
import { createFixture } from '../dist/core.js';
await mkdir(new URL('../qa/',import.meta.url),{recursive:true});
const fixture=await createFixture(2);
await writeFile(new URL('../qa/qa-import.img',import.meta.url),new Uint8Array(fixture.buffer));
if(process.argv[2]){
  const record=JSON.parse(await readFile(process.argv[2],'utf8'));
  record.payload.image.name='changed image name';
  await writeFile(new URL('../qa/tampered-record.json',import.meta.url),JSON.stringify(record,null,2));
}
