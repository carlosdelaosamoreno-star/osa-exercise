// Pantalla de bloqueo: PBKDF2-SHA256 + AES-GCM (Web Crypto). La clave derivada (no extraíble) se guarda en IndexedDB para el service worker.
const $=id=>document.getElementById(id),te=new TextEncoder();
const idb=(mode,fn)=>new Promise((ok,ko)=>{const o=indexedDB.open('osa-lock',1);o.onupgradeneeded=()=>o.result.createObjectStore('k');
 o.onsuccess=()=>{const t=o.result.transaction('k',mode),r=fn(t.objectStore('k'));t.oncomplete=()=>ok(r&&r.result);t.onerror=()=>ko(t.error)};o.onerror=()=>ko(o.error)});
const hex=h=>new Uint8Array(h.match(/../g).map(x=>parseInt(x,16)));
async function test(key){const b=new Uint8Array(await (await fetch('enc/index.bin',{cache:'no-store'})).arrayBuffer());
 const end=Math.min(b.length,12+(1<<20)+16);await crypto.subtle.decrypt({name:'AES-GCM',iv:b.slice(0,12),additionalData:te.encode('index|0')},key,b.slice(12,end));}
async function go(){await navigator.serviceWorker.register('sw.js');await navigator.serviceWorker.ready;location.replace('app/');}
function wait(){const n=+localStorage.osaFails||0,t=+localStorage.osaUntil||0,ms=t-Date.now();
 if(ms>0){$('b').disabled=true;$('m').textContent=`Demasiados intentos. Espera ${Math.ceil(ms/1000)} s`;setTimeout(wait,1000);return true}
 $('b').disabled=false;return false}
(async()=>{try{const s=await idb('readonly',o=>o.get('key'));if(s&&s.exp>Date.now()){await test(s.key);return go()}}catch(e){}
 if(location.hash==='#salir')$('m').textContent='Sesión cerrada';wait()})();
$('f').onsubmit=async e=>{e.preventDefault();if(wait())return;$('b').disabled=true;$('m').textContent='Comprobando…';
 try{const L=await (await fetch('lock.json',{cache:'no-store'})).json();
  const base=await crypto.subtle.importKey('raw',te.encode($('p').value),'PBKDF2',false,['deriveKey']);
  const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:hex(L.salt),iterations:L.iter,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['decrypt']);
  await test(key);localStorage.osaFails=0;
  await idb('readwrite',o=>o.put({key,exp:Date.now()+($('r').checked?365*864e5:12*36e5)},'key'));$('p').value='';await go();
 }catch(err){const n=(+localStorage.osaFails||0)+1;localStorage.osaFails=n;
  if(n>=5)localStorage.osaUntil=Date.now()+30000*2**Math.min(n-5,6);
  $('m').textContent='Contraseña incorrecta';$('b').disabled=false;wait()}};
