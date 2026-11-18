import {mkdir,copyFile} from 'node:fs/promises';
await mkdir('public',{recursive:true});
await copyFile('portal.html','public/index.html');

await copyFile('print.html','public/print.html');
