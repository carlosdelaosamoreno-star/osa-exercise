// SW raíz: sirve la app descifrando en memoria. En caché solo se guarda contenido cifrado.
const SCOPE=new URL('./',self.location).pathname,te=new TextEncoder(),ENC='osa-enc-v1';
let KEY=null,IDX=null,LAST={id:null,buf:null};
self.addEventListener('install',()=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil((async()=>{for(const k of await caches.keys())if(k!==ENC)await caches.delete(k);await self.clients.claim()})()));
const idb=(mode,fn)=>new Promise((ok,ko)=>{const o=indexedDB.open('osa-lock',1);o.onupgradeneeded=()=>o.result.createObjectStore('k');
 o.onsuccess=()=>{const t=o.result.transaction('k',mode),r=fn(t.objectStore('k'));t.oncomplete=()=>ok(r&&r.result);t.onerror=()=>ko(t.error)};o.onerror=()=>ko(o.error)});
self.addEventListener('message',e=>{if(e.data==='lock'){KEY=null;IDX=null;LAST={};e.waitUntil(idb('readwrite',o=>o.delete('key')))}});
async function getKey(){if(KEY)return KEY;const s=await idb('readonly',o=>o.get('key')).catch(()=>null);
 if(!s||s.exp<Date.now())return null;return KEY=s.key}
async function blob(name,fresh){const c=await caches.open(ENC),u=SCOPE+'enc/'+name;
 if(!fresh){const m=await c.match(u);if(m)return new Uint8Array(await m.arrayBuffer())}
 try{const r=await fetch(u,{cache:'no-cache'});if(!r.ok)throw 0;await c.put(u,r.clone());return new Uint8Array(await r.arrayBuffer())}
 catch(e){const m=await c.match(u);if(m)return new Uint8Array(await m.arrayBuffer());throw e}}
async function dec(buf,id,i,ch){const sz=12+ch+16,s=i*sz,b=buf.subarray(s,Math.min(s+sz,buf.length));
 return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:b.slice(0,12),additionalData:te.encode(id+'|'+i)},KEY,b.slice(12)))}
async function index(){if(IDX)return IDX;const b=await blob('index.bin',true);let parts=[],n=Math.ceil(b.length/(12+(1<<20)+16));
 for(let i=0;i<n;i++)parts.push(await dec(b,'index',i,1<<20));return IDX=JSON.parse(new TextDecoder().decode(await new Blob(parts).arrayBuffer()))}
async function serve(req,rel){if(!await getKey())return null;let I;try{I=await index()}catch(e){KEY=null;return null}
 if(rel===''||rel.endsWith('/'))rel+='index.html';const f=I.files[rel];if(!f)return new Response('No encontrado',{status:404});
 let buf=LAST.id===f.id?LAST.buf:await blob(f.id+'.bin');LAST={id:f.id,buf};
 const ch=I.ch,rg=/bytes=(\d*)-(\d*)/.exec(req.headers.get('range')||'');let s=0,e=f.n-1,st=200;
 if(rg&&f.n){s=rg[1]?+rg[1]:Math.max(0,f.n-+rg[2]);e=rg[1]&&rg[2]?Math.min(+rg[2],f.n-1):f.n-1;if(!rg[1])e=f.n-1;
  if(s>=f.n)return new Response(null,{status:416,headers:{'Content-Range':`bytes */${f.n}`}});st=206}
 const parts=[];for(let i=Math.floor(s/ch);i<=Math.floor(Math.max(e,0)/ch)&&f.n;i++){const d=await dec(buf,f.id,i,ch),o=i*ch;parts.push(d.subarray(Math.max(0,s-o),Math.min(d.length,e-o+1)))}
 const h={'Content-Type':f.t,'Accept-Ranges':'bytes','Cache-Control':'no-store','Content-Length':String(f.n?e-s+1:0)};if(st===206)h['Content-Range']=`bytes ${s}-${e}/${f.n}`;
 return new Response(new Blob(parts),{status:st,headers:h})}
self.addEventListener('fetch',e=>{const r=e.request,u=new URL(r.url);if(r.method!=='GET'||u.origin!==location.origin||!u.pathname.startsWith(SCOPE))return;
 const rel=decodeURIComponent(u.pathname.slice(SCOPE.length));
 if(rel===''||rel==='index.html'||rel==='lock.js'||rel==='lock.json'||rel==='sw.js'||rel==='manifest.webmanifest'||rel==='icon-192.png'||rel==='icon-512.png'||rel==='favicon.ico'||rel.startsWith('enc/'))return;
 if(r.mode==='navigate')IDX=null;// cada apertura relee el índice: nunca se queda una versión vieja en memoria
 e.respondWith(serve(r,rel).then(x=>x||(r.mode==='navigate'?Response.redirect(SCOPE,302):new Response('Bloqueado',{status:403}))).catch(()=>new Response('Error',{status:500})))});
