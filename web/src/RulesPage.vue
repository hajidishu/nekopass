<script setup lang="ts">
import { copyText } from './clipboard'
import { computed, reactive, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import Icon from './Icon.vue'
import { encodeNyanpassRules, parseRuleImport, prepareRuleImport } from './rule-transfer'
import { api as callAPI, bytes, address, quotaText, limitText, type Me, type User, type RuleNode, type Rule, type RuleInput, type Group } from './api'
const props = defineProps<{ me: Me; users: User[]; nodes: RuleNode[]; rules: Rule[]; managedUser?: User }>()
const emit = defineEmits<{ refresh: [] }>()
const protocolText = (value?: string) => value === 'dtls_udp' ? 'raw(udp) + TLS' : value === 'plain_udp' ? 'raw(udp) + 不加密' : value === 'tls_h2' ? 'h2 + TLS' : value === 'plain_h2' ? 'h2 + 不加密' : value === 'tls_tcp' ? 'raw(tcp) + TLS' : value === 'plain_tcp' ? 'raw(tcp) + 不加密' : '节点中转'
const actorID = computed(() => props.managedUser?.id || props.me.id)
async function api<T>(path: string, method = 'GET', body?: unknown): Promise<T> { return callAPI<T>(props.managedUser ? `admin/users/${props.managedUser.id}/${path}` : path, method, body) }

const owner = computed(() => actorID.value), group = ref(-1), query = ref(''), searching = ref(false), selected = ref<Rule[]>([]), busy = ref(false), page = ref(1), groups = ref<Group[]>([])
const ruleDialog = ref(false), editID = ref(0), targetText = ref(''), groupDialog = ref(false), importDialog = ref(false), importText = ref(''), batchDialog = ref(false), batchKind = ref('switch'), batchValue = ref(0), statsDialog = ref(false), details = ref<Rule | null>(null), advanced = ref<string[]>([])
const rowsPerPage = ref(20)
const ruleTable = ref<{ clearSelection: () => void }>()
const blank = (): RuleInput => ({ protocol:'tcp', user_id: actorID.value, node_id: 0, egress_node_id:0, name: '', group_id: 0, listen_port: 0, targets: [], balance: 'random', speed_mbps: 0, ip_limit: 0, connection_limit: 0, proxy_accept: 'off', proxy_send: 'off', proxy_trusted_cidrs: [], enabled: true })
const form = reactive<RuleInput>(blank())
const exportDialog = ref(false), exportFormat = ref('nyanpass'), exportRows = ref<RuleInput[]>([])
const importNodeID = ref(0), importEgressID = ref(0), importGroupID = ref(0), importRandomPorts = ref(false)
const importPreview = computed(() => {
  try { return { data: parseRuleImport(importText.value), error: '' } } catch (error) { return { data: null, error: (error as Error).message } }
})
const importAuthorizedNodes = computed(() => props.nodes.filter(n => policy.value?.node_ids.includes(n.id)))
const importIngressNodes = computed(() => importAuthorizedNodes.value.filter(n => n.ingress_enabled))
const importIngress = computed(() => importIngressNodes.value.find(n => n.id === importNodeID.value))
const importExitNodes = computed(() => importAuthorizedNodes.value.filter(n => n.id !== importNodeID.value && n.tunnel_exit_enabled && n.allowed_ingress_ids.includes(importNodeID.value)))
function selectImportIngress(id: number) { importNodeID.value = id; importEgressID.value = importIngress.value?.allow_direct ? 0 : importExitNodes.value[0]?.id || 0 }
function showImport() {
  if (!importIngress.value) selectImportIngress(importIngressNodes.value[0]?.id || 0)
  if (!ownGroups.value.some(g => g.id === importGroupID.value)) importGroupID.value = 0
  importDialog.value = true
}
const proxyVersions = reactive({ proxy_accept: 'v1', proxy_send: 'v1' })
function proxyToggle(field: 'proxy_accept' | 'proxy_send') {
  return computed({
    get: () => form[field] !== 'off',
    set: (enabled: boolean) => {
      if (form[field] !== 'off') proxyVersions[field] = form[field]
      form[field] = enabled ? proxyVersions[field] : 'off'
    }
  })
}
const proxyAcceptEnabled = proxyToggle('proxy_accept')
const proxySendEnabled = proxyToggle('proxy_send')
const groupForm = reactive({ name: '', user_id: owner.value || props.me.id })
const authorizedNodes = computed(() => props.nodes.filter(n => props.users.find(u => u.id === form.user_id)?.node_ids.includes(n.id)))
const eligibleNodes = computed(() => authorizedNodes.value.filter(n => n.ingress_enabled))
const batchIngressNodes = computed(() => props.nodes.filter(n => n.ingress_enabled))
const egressOptions = computed(() => authorizedNodes.value.filter(n => n.id !== form.node_id && n.tunnel_exit_enabled && n.allowed_ingress_ids.includes(form.node_id)&&(!n.tunnel_protocol?.endsWith('_udp')||form.protocol==='udp')))
const selectedIngress = computed(() => eligibleNodes.value.find(n => n.id === form.node_id))
function selectIngress(id:number){form.node_id=id;form.egress_node_id=selectedIngress.value?.allow_direct ? 0 : egressOptions.value[0]?.id || 0}
const ownRules = computed(() => props.rules.filter(r => r.user_id === actorID.value))
const ownGroups = computed(() => groups.value.filter(g => g.user_id === actorID.value))
const sortKey = ref(''), sortOrder = ref(''), statusFilter = ref<string[]>([])
const filtered = computed(() => {
  const rows = ownRules.value.filter(r => (group.value === -1 || (r.group_id || 0) === group.value) && (!statusFilter.value.length || statusFilter.value.includes(r.status)) && (!query.value || `${r.name} ${r.node_name} ${r.listen_port} ${r.targets.join(' ')} ${r.username}`.toLowerCase().includes(query.value.toLowerCase())))
  if (sortOrder.value && ['name', 'node_name', 'traffic_bytes'].includes(sortKey.value)) { const key = sortKey.value as 'name' | 'node_name' | 'traffic_bytes'; rows.sort((a, b) => (key === 'traffic_bytes' ? Number(a[key]) - Number(b[key]) : String(a[key]).localeCompare(String(b[key]))) * (sortOrder.value === 'ascending' ? 1 : -1)) }
  return rows
})
function sortChanged(v: {prop: string; order: string}) { sortKey.value = v.prop; sortOrder.value = v.order }
function filterChanged(v: Record<string, string[]>) { statusFilter.value = v.status || [] }
const paged = computed(() => filtered.value.slice((page.value - 1) * rowsPerPage.value, page.value * rowsPerPage.value))
const policy = computed(() => props.managedUser || props.users.find(u => u.id === actorID.value))
const scopedUsers = computed(() => policy.value ? [policy.value] : [])
const totalUsed = computed(() => scopedUsers.value.reduce((n, u) => n + Number(u.traffic_bytes), 0))
const totalQuota = computed(() => scopedUsers.value.reduce((n, u) => n + Number(u.quota_bytes), 0))
const maxRules = computed(() => scopedUsers.value.reduce((n, u) => n + u.max_rules, 0))
const nodeAddress = (r: Rule) => address(r.public_address || r.node_name, r.listen_port)
const statusText: Record<string, string> = { proxy_untrusted: '未配置信任来源', upgrade_required: '节点需升级', no_plan: '未分配套餐', plan_disabled: '套餐停用', unauthorized: '无入口权限', active: '正常', disabled: '已暂停', user_disabled: '用户停用', expired: '已到期', quota_exhausted: '流量耗尽', offline: '节点离线', failed: '同步失败', pending: '待同步' }
watch([owner, group, query, rowsPerPage, statusFilter, sortKey, sortOrder], () => { page.value = 1; selected.value = []; ruleTable.value?.clearSelection() })
watch(() => props.rules, () => { const live = new Map(props.rules.map(r => [r.id, r])); selected.value = selected.value.flatMap(r => live.has(r.id) ? [live.get(r.id)!] : []) })
watch(()=>form.protocol,()=>{if(form.protocol!=='tcp'){form.proxy_accept='off';form.proxy_send='off'};if(form.protocol!=='udp'&&props.nodes.find(n=>n.id===form.egress_node_id)?.tunnel_protocol?.endsWith('_udp'))form.egress_node_id=0})
watch(owner, () => { group.value = -1 })
async function action(f: () => Promise<void>) { busy.value = true; try { await f(); return true } catch (e) { ElMessage.error((e as Error).message); return false } finally { busy.value = false } }
async function loadGroups() { groups.value = await api<Group[]>('rule-groups') || [] }
void loadGroups().catch(e => ElMessage.error(e.message))
async function refresh() { emit('refresh'); await loadGroups() }
function inputOf(r: Rule): RuleInput { return { protocol:r.protocol||'tcp', user_id: r.user_id, node_id: r.node_id, egress_node_id:r.egress_node_id||0, name: r.name, group_id: r.group_id || 0, listen_port: r.listen_port, targets: [...r.targets], balance: r.balance, speed_mbps: 0, ip_limit: 0, connection_limit: 0, proxy_accept: r.proxy_accept, proxy_send: r.proxy_send, proxy_trusted_cidrs: [...r.proxy_trusted_cidrs], enabled: r.enabled } }
function edit(r?: Rule, copy = false) { editID.value = copy ? 0 : r?.id || 0; Object.assign(form, r ? inputOf(r) : blank()); proxyVersions.proxy_accept = form.proxy_accept === 'auto' ? 'auto' : form.proxy_accept === 'v2' ? 'v2' : 'v1'; proxyVersions.proxy_send = form.proxy_send === 'v2' ? 'v2' : 'v1'; if (copy) { form.listen_port = 0; form.name += ' 副本' }; targetText.value = form.targets.join('\n'); advanced.value = r ? ['advanced'] : []; ruleDialog.value = true }
async function save() { await action(async () => { form.listen_port = Number(form.listen_port) || 0; form.speed_mbps = Number(form.speed_mbps) || 0; form.targets = targetText.value.split(/\r?\n/).map(s => s.trim()).filter(Boolean); form.proxy_trusted_cidrs = []; await api(`rules${editID.value ? '/' + editID.value : ''}`, editID.value ? 'PUT' : 'POST', form); ruleDialog.value = false; await refresh(); ElMessage.success('规则已保存') }) }
async function batch(kind: string, ids = selected.value.map(r => r.id), extra = {}) { if (!ids.length) { ElMessage.warning('请先选择规则'); return }; if (kind === 'delete' || kind === 'clear') { try { await ElMessageBox.confirm(kind === 'clear' ? '清空选中规则的展示流量？用户已消耗额度不会返还，历史用量仍保留。' : `删除 ${ids.length} 条规则？现有连接将关闭。`, '确认操作', { confirmButtonText: '确定', cancelButtonText: '取消', type: 'warning' }) } catch { return } }; return await action(async () => { await api('rules/batch', 'POST', { ids, action: kind, ...extra }); selected.value = []; ruleTable.value?.clearSelection(); await refresh(); ElMessage.success('操作已完成') }) }
function showBatch(kind: string) { if (!selected.value.length) { ElMessage.warning('请先选择规则'); return }; batchKind.value = kind; batchValue.value = 0; batchDialog.value = true }
async function saveBatch() { const ok = await batch(batchKind.value, undefined, batchKind.value === 'group' ? { group_id: batchValue.value } : { node_id: batchValue.value }); if (ok) batchDialog.value = false }
async function rename(r: Rule) { try { const { value } = await ElMessageBox.prompt('规则名称', '重命名规则', { inputValue: r.name, confirmButtonText: '保存', cancelButtonText: '取消', inputValidator: v => !!v?.trim() || '请输入名称' }); await action(async () => { await api(`rules/${r.id}`, 'PUT', { ...inputOf(r), name: value }); await refresh() }) } catch { /* cancelled */ } }
async function copyAddress(r: Rule) { if (!r.public_address) { ElMessage.warning('请先由管理员在节点页配置公网地址'); return }; await action(async () => { await copyText(nodeAddress(r)); ElMessage.success('入口地址已复制') }) }
async function addGroup() { await action(async () => { await api('rule-groups', 'POST', groupForm); groupForm.name = ''; await loadGroups() }) }
async function renameGroup(g: Group) { try { const { value } = await ElMessageBox.prompt('分组名称', '修改分组', { inputValue: g.name, confirmButtonText: '保存', cancelButtonText: '取消' }); await action(async () => { await api(`rule-groups/${g.id}`, 'PUT', { name: value, user_id: g.user_id }); await loadGroups(); emit('refresh') }) } catch { /* cancelled */ } }
async function deleteGroup(g: Group) { try { await ElMessageBox.confirm('删除分组后，其中规则会移至未分组。', '删除分组', { confirmButtonText: '删除', cancelButtonText: '取消' }); await action(async () => { await api(`rule-groups/${g.id}`, 'DELETE', {}); if (group.value === g.id) group.value = -1; await refresh() }) } catch { /* cancelled */ } }
function showExport() { const rows = selected.value.length ? selected.value : filtered.value; if (!rows.length) { ElMessage.warning('没有可导出的规则'); return }; exportRows.value = rows.map(inputOf); exportFormat.value = 'nyanpass'; exportDialog.value = true }
async function exportRules() { await action(async () => {
  const compatible = exportFormat.value === 'nyanpass'
  const text = compatible ? encodeNyanpassRules(exportRows.value) : JSON.stringify({ rules: exportRows.value }, null, 2)
  const url = URL.createObjectURL(new Blob([text], { type: compatible ? 'application/x-ndjson' : 'application/json' }))
  const a = document.createElement('a'); a.href = url; a.download = compatible ? 'nyanpass-rules.jsonl' : 'nekopass-rules.json'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); exportDialog.value = false
}) }
async function fileImport(event: Event) { const file = (event.target as HTMLInputElement).files?.[0]; if (!file) return; if (file.size > 1024 * 1024) { ElMessage.error('文件不能超过 1 MiB'); return }; importText.value = await file.text() }
async function doImport() { await action(async () => {
  const data = parseRuleImport(importText.value)
  if (data.format === 'nyanpass' && (!importIngress.value || (!importIngress.value.allow_direct && !importEgressID.value) || (importEgressID.value && !importExitNodes.value.some(n => n.id === importEgressID.value)))) throw new Error('请选择可用的入口和出口')
  const rows = prepareRuleImport(data, { userID: actorID.value, nodeID: importNodeID.value, egressNodeID: importEgressID.value, groupID: importGroupID.value, trustedCIDRs: [], randomPorts: importRandomPorts.value })
  await api('rules/import', 'POST', { rules: rows }); importDialog.value = false; await refresh(); ElMessage.success('批量导入成功')
}) }
const stats = ref<{ time: string; bytes: number }[]>([]), statTitle = ref('最近 24 小时流量')
const statTotal = computed(() => stats.value.reduce((n, x) => n + Number(x.bytes), 0))
const chart = computed(() => { const now = new Date(); now.setMinutes(0, 0, 0); const map = new Map(stats.value.map(x => [new Date(x.time).getTime(), Number(x.bytes)])); const data = Array.from({ length: 24 }, (_, i) => { const time = new Date(now.getTime() - (23 - i) * 3600000); return { time, value: map.get(time.getTime()) || 0 } }); const max = Math.max(1, ...data.map(x => x.value)); return data.map((d, i) => ({ ...d, x: 30 + i * 24, height: d.value / max * 140 })) })
async function showStats(r?: Rule) { await action(async () => { stats.value = await api(`rules/stats${r ? '?rule_id=' + r.id : owner.value ? '?user_id=' + owner.value : ''}`) || []; statTitle.value = `${r ? r.name + ' · ' : ''}最近 24 小时流量`; statsDialog.value = true }) }
</script>

<template>
  <section class="rules-panel surface">
    <div class="rules-titlebar"><strong>{{ managedUser ? managedUser.username + ' 的转发规则' : '我的转发规则' }}</strong><el-button @click="searching = !searching"><Icon name="search" />搜索规则</el-button><el-button :loading="busy" @click="action(refresh)"><Icon name="refresh" />刷新</el-button><el-button @click="showStats()"><Icon name="stats" />统计数据</el-button></div>
    <div class="rules-content">
      <el-input v-if="searching" v-model="query" class="rule-search" placeholder="搜索名称、入口、端口、目标或用户" clearable autofocus />
      <div class="rules-meta"><span class="meta-chip">流量: {{ bytes(totalUsed) }} / {{ policy?.plan_id ? quotaText(totalQuota) : '未分配套餐' }}</span><span class="meta-chip">到期: {{ !policy?.plan_id ? '未分配套餐' : policy.expires_at ? new Date(policy.expires_at).toLocaleString() : '永不到期' }}</span><span class="meta-chip">规则数: {{ ownRules.length }} / {{ policy?.plan_id ? limitText(maxRules) : '—' }}</span><el-button class="group-manage" @click="groupForm.user_id = actorID; groupDialog = true"><Icon name="folder" />管理分组</el-button><button class="group-tab" :class="{ active: group === -1 }" @click="group = -1">全部</button><button class="group-tab" :class="{ active: group === 0 }" @click="group = 0">未分组 ({{ ownRules.filter(r => !r.group_id).length }})</button><button v-for="g in ownGroups" :key="g.id" class="group-tab" :class="{ active: group === g.id }" @click="group = g.id">{{ g.name }} ({{ ownRules.filter(r => r.group_id === g.id).length }})</button></div>
      <div class="rule-toolbar"><el-button @click="edit()"><Icon name="add" />添加规则</el-button><el-button @click="showImport"><Icon name="upload" />批量导入</el-button><el-button @click="showExport"><Icon name="download" />批量导出</el-button><el-button @click="showBatch('switch')"><Icon name="switch" />批量切换</el-button><el-button :disabled="busy || !selected.length" @click="batch('disable')"><Icon name="pause" />暂停选中</el-button><el-button :disabled="busy || !selected.length" @click="batch('enable')"><Icon name="play" />恢复选中</el-button><el-button @click="batch('clear')"><Icon name="clear" />清空流量</el-button><el-button @click="batch('delete')"><Icon name="delete" />删除选中</el-button><span v-if="selected.length" class="selection-note">已选择 {{ selected.length }} 条</span></div>
      <el-table ref="ruleTable" :data="paged" row-key="id" @selection-change="selected = $event" @sort-change="sortChanged" @filter-change="filterChanged" empty-text="暂无转发规则，点击「添加规则」开始。" class="rules-table"><el-table-column type="selection" width="40" :reserve-selection="true" /><el-table-column prop="name" label="规则名" min-width="210" sortable="custom"><template #default="{ row }"><span>{{ row.name }} <small>(#{{ row.id }})</small></span><div v-if="me.is_admin && !owner" class="subtle small">{{ row.username }}</div></template></el-table-column><el-table-column prop="protocol" label="协议" width="90"><template #default="{ row }">{{ row.protocol==='udp'?'UDP':'TCP' }}</template></el-table-column><el-table-column prop="node_name" label="入口" min-width="210" sortable="custom"><template #default="{ row }"><div>入口: {{ row.node_name }} <span class="entry-badge">{{ row.egress_node_id ? '出口: '+row.egress_node_name : '直转' }}</span></div><button class="address-link" @click="copyAddress(row)" :title="row.public_address ? '复制入口地址' : '节点尚未配置公网地址'">{{ nodeAddress(row) }}</button></template></el-table-column><el-table-column label="出口" min-width="190"><template #default="{ row }"><div v-for="target in row.targets" :key="target">{{ target }}</div></template></el-table-column><el-table-column prop="traffic_bytes" label="已用流量" width="130" sortable="custom"><template #default="{ row }">{{ bytes(row.traffic_bytes) }}</template></el-table-column><el-table-column prop="status" column-key="status" :filtered-value="statusFilter" label="状态" width="115" :filters="Object.entries(statusText).map(([value, text]) => ({ value, text }))" :filter-method="() => true"><template #default="{ row }"><span :class="['rule-status', row.status]">{{ statusText[row.status] || row.status }}</span></template></el-table-column><el-table-column label="操作" width="246"><template #default="{ row }"><div class="row-actions"><el-button :aria-label="row.enabled ? '暂停规则' : '恢复规则'" :title="row.enabled ? '暂停' : '恢复'" @click="batch(row.enabled ? 'disable' : 'enable', [row.id])"><Icon :name="row.enabled ? 'pause' : 'play'" /></el-button><el-button title="规则详情" aria-label="规则详情" @click="details = row"><Icon name="help" /></el-button><el-button title="复制规则" aria-label="复制规则" @click="edit(row, true)"><Icon name="copy" /></el-button><el-button title="编辑规则" aria-label="编辑规则" @click="edit(row)"><Icon name="edit" /></el-button><el-button title="重命名" aria-label="重命名" @click="rename(row)"><Icon name="rename" /></el-button><el-button title="删除规则" aria-label="删除规则" @click="batch('delete', [row.id])"><Icon name="delete" /></el-button></div></template></el-table-column></el-table>
      <div class="rules-pagination"><span class="subtle">共 {{ filtered.length }} 条规则</span><el-pagination v-model:current-page="page" v-model:page-size="rowsPerPage" :page-sizes="[20, 50, 100]" :total="filtered.length" layout="sizes, prev, pager, next" /></div>
    </div>
  </section>
  <div class="rule-dock" aria-label="规则快捷操作"><button @click="showBatch('group')"><Icon name="folder" />分组</button><button @click="edit()"><Icon name="add" />单条</button><button @click="showImport"><Icon name="upload" />批量</button><button @click="showExport"><Icon name="download" />导出</button><button @click="showBatch('switch')"><Icon name="switch" />切换</button><button @click="batch('clear')"><Icon name="clear" />流量</button><button @click="batch('disable')"><Icon name="pause" />暂停</button><button @click="batch('enable')"><Icon name="play" />恢复</button><button @click="batch('delete')"><Icon name="delete" />删除</button></div>
  <el-dialog v-model="ruleDialog" :title="editID ? '编辑规则' : '添加规则'" width="416px" top="4vh" class="rule-form-dialog"><el-form label-position="top" @submit.prevent="save"><el-form-item label="转发类型"><el-select v-model="form.protocol"><el-option label="TCP" value="tcp"/><el-option label="UDP" value="udp"/></el-select></el-form-item><el-form-item label="名称"><el-input v-model="form.name" maxlength="128" /></el-form-item><el-form-item label="入口"><el-select :model-value="form.node_id || undefined" @update:model-value="selectIngress($event)" placeholder="请选择入口节点"><el-option v-for="n in eligibleNodes" :key="n.id" :label="n.name" :value="n.id" /></el-select></el-form-item><el-form-item label="出口"><el-select v-model="form.egress_node_id" :disabled="!form.node_id" placeholder="请选择出口"><el-option v-if="selectedIngress?.allow_direct" label="#0 不使用隧道，直接转发" :value="0" /><el-option v-for="n in egressOptions" :key="n.id" :label="n.name + ' · ' + protocolText(n.tunnel_protocol)" :value="n.id" /></el-select><span v-if="form.node_id && !selectedIngress?.allow_direct && !egressOptions.length" class="field-tip">此入口没有可选出口，请联系管理员配置节点关联。</span></el-form-item><el-form-item label="监听端口"><el-input :model-value="form.listen_port || ''" @update:model-value="form.listen_port = Number($event) || 0" placeholder="留空则随机" type="number" :min="0" :max="65535" /><span class="field-tip">0 或留空自动分配（{{ eligibleNodes.find(n => n.id === form.node_id)?.port_min || 1024 }}–{{ eligibleNodes.find(n => n.id === form.node_id)?.port_max || 65535 }}）</span></el-form-item><el-form-item label="目标地址"><el-input v-model="targetText" type="textarea" :rows="5" placeholder="一行一个，空行会被忽略，格式如下：&#10;&#10;1.2.3.4:5678&#10;[2001::]:80&#10;example.com:443" /></el-form-item><el-collapse v-model="advanced" class="advanced-options"><el-collapse-item title="高级选项" name="advanced"><el-form-item label="负载均衡策略"><el-select v-model="form.balance"><el-option label="随机" value="random" /><el-option label="轮询" value="round_robin" /><el-option label="最少连接" value="least_connections" /></el-select></el-form-item><el-form-item v-if="form.protocol==='tcp'" label="接受 Proxy Protocol"><el-select v-model="proxyAcceptEnabled"><el-option label="关闭" :value="false" /><el-option label="开启" :value="true" /></el-select></el-form-item><p class="field-tip">PROXY Protocol 信任来源由管理员统一配置。</p><el-form-item v-if="form.protocol==='tcp'" label="发送 Proxy Protocol"><el-select v-model="proxySendEnabled"><el-option label="关闭" :value="false" /><el-option label="开启" :value="true" /></el-select></el-form-item><div class="field-tip">资源限制初始来自套餐「{{ policy?.plan_name || '未分配' }}」，个人设置由管理员调整。规则限速 {{ policy?.rule_speed_mbps ? policy.rule_speed_mbps + ' Mbps' : '不额外限制' }}，IP 上限 {{ policy?.rule_ip_limit || '不限' }}，连接数上限 {{ policy?.rule_connection_limit || '不限' }}。</div><el-form-item label="分组"><el-select v-model="form.group_id"><el-option label="未分组" :value="0" /><el-option v-for="g in groups.filter(g => g.user_id === form.user_id)" :key="g.id" :label="g.name" :value="g.id" /></el-select></el-form-item></el-collapse-item></el-collapse></el-form><template #footer><el-button @click="ruleDialog = false">取消</el-button><el-button type="primary" :loading="busy" @click="save">确定</el-button></template></el-dialog>
  <el-dialog v-model="groupDialog" title="管理分组" width="540px"><el-form :inline="true"><el-form-item><el-input v-model="groupForm.name" placeholder="分组名称" maxlength="64" /></el-form-item><el-button type="primary" :loading="busy" @click="addGroup">添加</el-button></el-form><el-table :data="groups.filter(g => g.user_id === actorID)"><el-table-column prop="name" label="名称" /><el-table-column prop="rule_count" label="规则数" width="90" /><el-table-column label="操作" width="120"><template #default="{ row }"><el-button link @click="renameGroup(row)">编辑</el-button><el-button link type="danger" @click="deleteGroup(row)">删除</el-button></template></el-table-column></el-table></el-dialog>
  <el-dialog v-model="importDialog" title="批量导入规则" width="620px">
    <p class="subtle">支持 nyanpass 逐行 JSON 和 Nekopass 完整备份。最多 500 条；失败时整批回滚。</p>
    <input type="file" accept="application/json,application/x-ndjson,text/plain,.json,.jsonl,.ndjson,.txt" @change="fileImport" />
    <el-input v-model="importText" type="textarea" :rows="8" placeholder='{"dest":["example.com:443"],"listen_port":9122,"name":"示例","proxy_protocol":3}' class="import-text" />
    <p v-if="importPreview.data" class="subtle">已识别 {{ importPreview.data.format === 'nyanpass' ? 'nyanpass' : 'Nekopass' }} 格式，共 {{ importPreview.data.rules.length }} 条。</p>
    <p v-else-if="importText.trim()" class="field-tip">{{ importPreview.error }}</p>
    <p v-if="importPreview.data?.format === 'nyanpass' && importPreview.data.rules.some(r => r.proxy_protocol === 2)" class="field-tip">发送 v2 TCP+UDP 将按 v2 TCP 导入，该导入格式未提供转发类型，仍按 TCP 导入；UDP 请使用 Nekopass 完整备份。</p>
    <el-form v-if="importPreview.data?.format === 'nyanpass'" label-position="top">
      <el-form-item label="入口"><el-select :model-value="importNodeID || undefined" @update:model-value="selectImportIngress($event)" placeholder="请选择入口节点"><el-option v-for="n in importIngressNodes" :key="n.id" :label="n.name" :value="n.id" /></el-select></el-form-item>
      <el-form-item label="出口"><el-select v-model="importEgressID" :disabled="!importNodeID"><el-option v-if="importIngress?.allow_direct" label="#0 不使用隧道，直接转发" :value="0" /><el-option v-for="n in importExitNodes" :key="n.id" :label="n.name + ' · ' + protocolText(n.tunnel_protocol)" :value="n.id" /></el-select></el-form-item>
      <el-form-item label="分组"><el-select v-model="importGroupID"><el-option label="未分组" :value="0" /><el-option v-for="g in ownGroups" :key="g.id" :label="g.name" :value="g.id" /></el-select></el-form-item>
      <p class="field-tip">PROXY Protocol 信任来源由管理员统一配置。</p>
      <el-checkbox v-model="importRandomPorts">重新随机分配监听端口</el-checkbox>
    </el-form>
    <template #footer><el-button @click="importDialog = false">取消</el-button><el-button type="primary" :loading="busy" :disabled="!importPreview.data" @click="doImport">导入</el-button></template>
  </el-dialog>
  <el-dialog v-model="exportDialog" title="批量导出规则" width="520px">
    <p>导出 {{ exportRows.length }} 条规则。</p>
    <el-radio-group v-model="exportFormat"><el-radio value="nyanpass">nyanpass 兼容格式</el-radio><el-radio value="nekopass">Nekopass 完整备份</el-radio></el-radio-group>
    <p class="subtle">{{ exportFormat === 'nyanpass' ? '一行一个 JSON，包含目标、监听端口、名称和 Proxy Protocol 开关；入口、出口、分组、启停及接收版本限制不包含在内。' : '保留入口、出口、分组、启停状态及高级选项。' }}</p>
    <template #footer><el-button @click="exportDialog = false">取消</el-button><el-button type="primary" :loading="busy" @click="exportRules">导出</el-button></template>
  </el-dialog>
  <el-dialog v-model="batchDialog" :title="batchKind === 'group' ? '移动选中规则到分组' : '批量切换入口'" width="440px"><p class="subtle">{{ batchKind === 'group' ? '选中的规则和分组必须属于同一用户。' : '切换后重新分配监听端口，旧连接将关闭。目标入口必须已授权，且支持规则现有的出口。' }}</p><el-select v-model="batchValue"><el-option v-if="batchKind === 'group'" label="未分组" :value="0" /><el-option v-for="item in batchKind === 'group' ? ownGroups : batchIngressNodes" :key="item.id" :label="item.name" :value="item.id" /></el-select><template #footer><el-button @click="batchDialog = false">取消</el-button><el-button type="primary" :loading="busy" @click="saveBatch">确定</el-button></template></el-dialog>
  <el-dialog :model-value="!!details" title="规则详情" width="560px" @close="details = null"><template v-if="details"><el-descriptions :column="1" border><el-descriptions-item label="名称">{{ details.name }}</el-descriptions-item><el-descriptions-item label="入口">{{ nodeAddress(details) }}</el-descriptions-item><el-descriptions-item label="出口">{{ details.egress_node_id ? details.egress_node_name+' · '+protocolText(details.egress_tunnel_protocol) : '#0 直转' }}</el-descriptions-item><el-descriptions-item label="目标">{{ details.targets.join(', ') }}</el-descriptions-item><el-descriptions-item label="状态">{{ statusText[details.status] }}</el-descriptions-item><el-descriptions-item label="同步反馈">{{ details.sync_error || '无错误' }}</el-descriptions-item><el-descriptions-item label="规则限速">{{ details.speed_mbps || '不限' }} {{ details.speed_mbps ? 'Mbps' : '' }}</el-descriptions-item><el-descriptions-item label="IP / 连接数限制">{{ details.ip_limit || '不限' }} / {{ details.connection_limit || '不限' }}</el-descriptions-item><el-descriptions-item label="已用流量">{{ bytes(details.traffic_bytes) }}</el-descriptions-item></el-descriptions><el-button class="detail-stats" @click="showStats(details!)"><Icon name="stats" />查看统计数据</el-button></template></el-dialog>
  <el-dialog v-model="statsDialog" :title="statTitle" width="680px"><p>合计 {{ bytes(statTotal) }}</p><svg class="traffic-chart" viewBox="0 0 620 210" role="img" :aria-label="statTitle"><path d="M25 15V170H610" fill="none" stroke="currentColor" opacity=".25" /><g v-for="(bar, i) in chart" :key="i"><rect :x="bar.x" :y="170 - bar.height" width="15" :height="Math.max(1, bar.height)" rx="2" fill="#78b3f7"><title>{{ bar.time.toLocaleString() }} · {{ bytes(bar.value) }}</title></rect><text v-if="i % 4 === 0" :x="bar.x" y="193" font-size="10" fill="currentColor">{{ bar.time.getHours() }}:00</text></g></svg><p class="subtle">按小时汇总实际转发字节。开始采集后才有历史数据；清空规则展示流量不会删除历史记录。</p></el-dialog>
</template>
