'use client';
import { useCallback, useEffect, useState } from 'react';
type Client={oauth_client_id:string;application_name:string;enabled:boolean;http_redirects:string[]};
const endpoint='/api/nexus/registry/applications/dev-redirects';
export function DevRedirectManager(){
 const [clients,setClients]=useState<Client[]>([]),[selected,setSelected]=useState(''),[uri,setUri]=useState('');
 const [busy,setBusy]=useState(false),[error,setError]=useState(''),[message,setMessage]=useState('');
 const load=useCallback(async()=>{const r=await fetch(endpoint,{cache:'no-store'});const d=await r.json();if(!r.ok)throw new Error(d.error||'Unable to load clients');setClients(d.clients);},[]);
 useEffect(()=>{void load().catch(e=>setError(String(e)));},[load]);
 const c=clients.find(x=>x.oauth_client_id===selected);
 async function change(action:'enable'|'disable'|'add'|'remove',redirect?:string){
  if(action==='enable'&&!window.confirm('Enable insecure HTTP redirects for this DEVELOPMENT client? Authorization codes will transit your local network over HTTP. Use a trusted LAN and PKCE S256.'))return;
  if(action==='remove'&&!window.confirm(`Remove approved callback ${redirect}?`))return;
  setBusy(true);setError('');setMessage('');
  try{
   const r=await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify({clientId:selected,action,uri:redirect,confirmInsecureDev:action==='enable'})});
   const d=await r.json();if(!r.ok)throw new Error(d.error||'Request failed');
   setMessage('Saved. The next OAuth authorization request uses this setting.');
   if(action==='add')setUri('');await load();
  }catch(e){setError(e instanceof Error?e.message:'Request failed');}finally{setBusy(false);}
 }
 return <div className="stack">
  <label htmlFor="dev-client">Development OAuth client</label>
  <select id="dev-client" value={selected} onChange={e=>setSelected(e.target.value)}>
   <option value="">Select a client</option>{clients.map(c=><option key={c.oauth_client_id} value={c.oauth_client_id}>{c.application_name} — {c.oauth_client_id}</option>)}
  </select>
  {c&&<div className="identity-box">
    <p><strong>Insecure development redirects:</strong> {c.enabled?'Enabled':'Disabled'}</p>
    <button className="button secondary" type="button" disabled={busy} onClick={()=>void change(c.enabled?'disable':'enable')}>
      {c.enabled?'Disable capability':'Enable capability (acknowledge risk)'}
    </button>
    <p className="muted small">Only exact registered private IPv4 or localhost HTTP callbacks are accepted. Do not use a public network, and never store client secrets in browser code.</p>
    <form className="admin-form" onSubmit={e=>{e.preventDefault();void change('add',uri.trim());}}>
      <label htmlFor="lan-uri">Approved HTTP callback URI</label>
      <input id="lan-uri" value={uri} onChange={e=>setUri(e.target.value)} required
        placeholder="http://192.168.1.50:3000/auth/callback"/>
      <button className="button" type="submit" disabled={busy}>Add exact callback</button>
    </form>
    <ul className="admin-list">{c.http_redirects.map(r=><li key={r}><code>{r}</code><button className="button secondary" type="button" disabled={busy} onClick={()=>void change('remove',r)}>Remove</button></li>)}</ul>
  </div>}
  {error&&<p role="alert" className="error">{error}</p>}{message&&<p className="muted" role="status">{message}</p>}
 </div>;
}
