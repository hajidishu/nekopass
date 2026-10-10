import type { RuleInput } from './api'

export type NyanpassRule = { dest: string[]; listen_port: number; name: string; proxy_protocol?: number; accept_proxy_protocol?: number }
type LegacyRuleInput = Omit<RuleInput, 'protocol'> & { protocol?: RuleInput['protocol'] | 'tcp_udp' }
export type RuleImport = { format: 'nyanpass'; rules: NyanpassRule[] } | { format: 'nekopass'; rules: LegacyRuleInput[] }
export type ImportDestination = { userID: number; nodeID: number; egressNodeID: number; groupID: number; trustedCIDRs: string[]; randomPorts: boolean }

// Values are verified against Nyanpass exports; unknown modes must never be guessed.
const proxySendModes: Record<number, string> = {
  0: 'off', 1: 'v1', 2: 'v2', 3: 'v2',
}
const nyanpassFields = new Set(['dest', 'listen_port', 'name', 'proxy_protocol', 'accept_proxy_protocol'])
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)

export function nyanpassNeedsProxyTrust(data: RuleImport): boolean {
  return data.format === 'nyanpass' && data.rules.some(r => r.accept_proxy_protocol === 1)
}

export function parseRuleImport(text: string): RuleImport {
  if (new TextEncoder().encode(text).length > 1024 * 1024) throw new Error('导入内容不能超过 1 MiB')
  const content = text.replace(/^\uFEFF/, '').trim()
  if (!content) throw new Error('请粘贴规则或选择文件')
  let data: unknown
  try { data = JSON.parse(content) } catch {
    data = content.split(/\r?\n/).flatMap((line, index) => {
      if (!line.trim()) return []
      try { return [JSON.parse(line)] } catch { throw new Error(`第 ${index + 1} 行不是有效的 JSON`) }
    })
  }
  const rows = Array.isArray(data) ? data : object(data) && Array.isArray(data.rules) ? data.rules : [data]
  if (!rows.length || rows.length > 500) throw new Error('每次导入 1–500 条规则')
  if (rows.some(v => !object(v))) throw new Error('每条规则必须是 JSON 对象')
  const nyanpass = rows.some(v => Object.hasOwn(v, 'dest'))
  if (!nyanpass) {
    if (rows.some(v => !Array.isArray(v.targets))) throw new Error('请输入 nyanpass 逐行 JSON，或 Nekopass 规则备份')
    if (rows.some(v => v.protocol !== undefined && !['tcp', 'udp', 'tcp_udp'].includes(v.protocol as string))) throw new Error('转发类型只支持 TCP 或 UDP')
    return { format: 'nekopass', rules: rows as LegacyRuleInput[] }
  }
  rows.forEach((v, index) => {
    const fail = (message: string): never => { throw new Error(`第 ${index + 1} 条：${message}`) }
    if (!Array.isArray(v.dest) || !v.dest.length || v.dest.length > 32 || v.dest.some((t: unknown) => typeof t !== 'string')) fail('dest 必须包含 1–32 个目标地址')
    if (typeof v.name !== 'string') fail('name 必须是字符串')
    if (!Number.isInteger(v.listen_port) || (v.listen_port as number) < 0 || (v.listen_port as number) > 65535) fail('listen_port 必须为 0–65535 的整数')
    const extra = Object.keys(v).filter(k => !nyanpassFields.has(k))
    if (extra.length) fail(`暂不支持 nyanpass 字段 ${extra.join('、')}，请核对后移除`)
    if (v.proxy_protocol !== undefined && (!Number.isInteger(v.proxy_protocol) || !Object.hasOwn(proxySendModes, v.proxy_protocol as number))) fail('proxy_protocol 只支持 0、1、2、3')
    if (v.accept_proxy_protocol !== undefined && v.accept_proxy_protocol !== 0 && v.accept_proxy_protocol !== 1) fail('accept_proxy_protocol 只支持 0、1')
  })
  return { format: 'nyanpass', rules: rows as NyanpassRule[] }
}

export function prepareRuleImport(data: RuleImport, destination: ImportDestination): RuleInput[] {
  if (data.format === 'nekopass') {
    const rules = data.rules.flatMap(r => {
      if (r.protocol === 'tcp_udp' && !r.listen_port) throw new Error('旧合并规则请填写共同监听端口')
      const protocols: ('tcp' | 'udp')[] = r.protocol === 'tcp_udp' ? ['tcp', 'udp'] : [r.protocol || 'tcp']
      return protocols.map(protocol => ({ ...r, protocol, user_id: destination.userID, targets: [...r.targets] }))
    })
    if (rules.length > 500) throw new Error('拆分后每次最多导入 500 条规则')
    return rules
  }
  if (!destination.nodeID) throw new Error('请选择导入规则的入口节点')
  return data.rules.map(r => {
    const accept = r.accept_proxy_protocol === 1 ? 'auto' : 'off'
    const send = proxySendModes[r.proxy_protocol ?? 0]
    if (send === undefined) throw new Error('不支持此 proxy_protocol 数值')
    return {
      user_id: destination.userID, node_id: destination.nodeID, egress_node_id: destination.egressNodeID,
      name: r.name, group_id: destination.groupID, listen_port: destination.randomPorts ? 0 : r.listen_port,
      targets: [...r.dest], balance: 'random', speed_mbps: 0, ip_limit: 0, connection_limit: 0,
      proxy_accept: accept, proxy_send: send, proxy_trusted_cidrs: [], enabled: true,
    }
  })
}

export function encodeNyanpassRules(rules: RuleInput[]): string {
  return rules.map(r => {
 if(r.protocol&&r.protocol!=='tcp')throw new Error(`规则「${r.name}」请使用 Nekopass 完整备份导出 UDP 类型`)
    if (!['off', 'auto', 'v1', 'v2'].includes(r.proxy_accept) || !['off', 'v1', 'v2'].includes(r.proxy_send)) throw new Error(`规则「${r.name}」的 Proxy Protocol 模式无法兼容导出`)
    const row: NyanpassRule = { dest: [...r.targets], listen_port: r.listen_port, name: r.name }
    if (r.proxy_send !== 'off') row.proxy_protocol = r.proxy_send === 'v1' ? 1 : 3
    if (r.proxy_accept !== 'off') row.accept_proxy_protocol = 1
    return JSON.stringify(row)
  }).join('\n') + '\n'
}
