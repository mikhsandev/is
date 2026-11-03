import { headers } from 'next/headers';
import { redirect } from 'next/navigation';
import { currentNexusOperatorId } from '@/lib/nexus-operator-access';
import { DevRedirectManager } from './manager';
export const dynamic='force-dynamic';
export default async function Page(){
  if(!await currentNexusOperatorId(await headers())) redirect('/');
  return <section className="panel admin-panel">
    <p className="eyebrow">IS · Nexus · Applications</p>
    <h1>Development HTTP callbacks</h1>
    <p className="muted">Explicitly approve private/LAN callbacks for development OAuth clients only. Production and staging remain HTTPS-only.</p>
    <DevRedirectManager/>
  </section>;
}
