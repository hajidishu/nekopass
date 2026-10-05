import type { Plan, User } from './api'
const GiB = 1024 ** 3
const roundedGiB = (bytes: number) => bytes === -1 ? -1 : Number((bytes / GiB).toFixed(6))
export const resourceFields = ['speed_mbps','max_rules','max_connections','ip_limit','rule_speed_mbps','rule_ip_limit','rule_connection_limit'] as const
export type ResourceForm = Record<typeof resourceFields[number], number> & { quota_gib: number; traffic_gib: string; expires_at: string; node_group_ids: number[] }
export function resourcesOf(user?: User): ResourceForm {
  return { speed_mbps:user?.speed_mbps||0,max_rules:user?.max_rules||0,max_connections:user?.max_connections||0,ip_limit:user?.ip_limit||0,rule_speed_mbps:user?.rule_speed_mbps||0,rule_ip_limit:user?.rule_ip_limit||0,rule_connection_limit:user?.rule_connection_limit||0,quota_gib:roundedGiB(user?.quota_bytes||0),traffic_gib:((user?.traffic_bytes||0)/GiB).toFixed(6),expires_at:user?.expires_at||'',node_group_ids:[...(user?.node_group_ids||[])] }
}
export function planResources(plan?: Plan): Omit<ResourceForm,'traffic_gib'> {
  return { speed_mbps:plan?.speed_mbps||0,max_rules:plan?.max_rules||0,max_connections:plan?.max_connections||0,ip_limit:plan?.ip_limit||0,rule_speed_mbps:plan?.rule_speed_mbps||0,rule_ip_limit:plan?.rule_ip_limit||0,rule_connection_limit:plan?.rule_connection_limit||0,quota_gib:roundedGiB(plan?.quota_bytes||0),expires_at:plan?.duration_days ? new Date(Date.now()+plan.duration_days*86400000).toISOString() : '',node_group_ids:[...(plan?.node_group_ids||[])] }
}
export function resourceChanges(form: ResourceForm, original?: ResourceForm): Record<string,unknown> {
  const result: Record<string,unknown> = {}
  for (const field of resourceFields) if (!original || form[field]!==original[field]) result[field]=form[field]
  if (!original || form.quota_gib!==original.quota_gib) result.quota_bytes=form.quota_gib===-1?-1:Math.round(form.quota_gib*GiB)
  if ((!original && Number(form.traffic_gib)!==0) || (original && form.traffic_gib!==original.traffic_gib)) {
    const value=form.traffic_gib.trim() || '0'
    if (!/^\d+(\.\d{1,9})?$/.test(value) || !Number.isFinite(Number(value)) || Number(value)>2**30) throw new Error('已用流量须为非负数值')
    result.traffic_bytes=Math.round(Number(value)*GiB)
  }
  const dateValue=(s:string)=>s?new Date(s).getTime():0
  if (!original || dateValue(form.expires_at)!==dateValue(original.expires_at)) result.expires_at=form.expires_at||''
  if (!original || JSON.stringify([...form.node_group_ids].sort((a,b)=>a-b))!==JSON.stringify([...original.node_group_ids].sort((a,b)=>a-b))) result.node_group_ids=[...form.node_group_ids]
  return result
}
