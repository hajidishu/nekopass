<script setup lang="ts">
import {ref,reactive,computed} from 'vue'
import {ElMessage} from 'element-plus'
import {yuan,requestKey} from '../commerce'
import PageShell from '../PageShell.vue'
import Icon from '../Icon.vue'
import LimitInput from '../LimitInput.vue'
import { resourcesOf, planResources, resourceChanges, type ResourceForm } from '../user-resource-form'
import {usePage} from '../page'
import {api,bytes,quotaText,limitText,type User,type Plan,type NodeGroup} from '../api'
const users=ref<User[]>([]),plans=ref<Plan[]>([]),userPage=ref(1),search=ref(''),dialog=ref(false),editID=ref(0)
const resource=reactive(resourcesOf()),originalResource=ref<ResourceForm>(),originalUser=ref<User>(),nodeGroups=ref<NodeGroup[]>([])
const form=reactive({username:'',password:'',enabled:true,plan_id:0})
const rechargeDialog=ref(false),rechargeUser=ref<User|null>(null),recharge=reactive({amount:'100.00',note:'',request_key:''})
function credit(u:User){rechargeUser.value=u;Object.assign(recharge,{amount:'100.00',note:'',request_key:requestKey()});rechargeDialog.value=true}
async function saveCredit(){if(!rechargeUser.value)return;await run(async()=>{await api(`admin/users/${rechargeUser.value!.id}/recharge`,'POST',recharge);rechargeDialog.value=false;await refresh();ElMessage.success('充值成功，已记入余额明细')})}
const filtered=computed(()=>users.value.filter(u=>u.username.toLowerCase().includes(search.value.toLowerCase())))
const paged=computed(()=>filtered.value.slice((userPage.value-1)*25,userPage.value*25))
const {me,loading,error,busy,run,refresh}=usePage(async()=>{const[u,p,g]=await Promise.all([api<User[]>('admin/users'),api<Plan[]>('admin/plans'),api<NodeGroup[]>('admin/node-groups')]);users.value=u;plans.value=p;nodeGroups.value=g},{admin:true,interval:5000})
function edit(u?:User){editID.value=u?.id||0;originalUser.value=u;originalResource.value=u?resourcesOf(u):undefined;Object.assign(resource,resourcesOf(u));Object.assign(form,{username:u?.username||'',password:'',enabled:u?.enabled??true,plan_id:u?.plan_id||0});dialog.value=true}
function selectPlan(id:number){form.plan_id=id;Object.assign(resource,id===originalUser.value?.plan_id?resourcesOf(originalUser.value):planResources(plans.value.find(p=>p.id===id)))}
async function save(){await run(async()=>{
 const changes=resourceChanges(resource,form.plan_id===originalUser.value?.plan_id?originalResource.value:undefined)
 if(resource.traffic_gib===originalResource.value?.traffic_gib)delete changes.traffic_bytes
 await api(`admin/users${editID.value?'/'+editID.value:''}`,editID.value?'PUT':'POST',{...form,...changes,...(editID.value?{expected_resources_revision:originalUser.value?.resources_revision}: {})})
 dialog.value=false;await refresh();ElMessage.success('用户已保存')
})}
</script>
<template><PageShell :me="me" :loading="loading" :error="error" active="users" admin><section class="surface"><div class="section-header"><strong>用户管理</strong><el-button @click="edit()"><Icon name="add" />创建用户</el-button></div><div class="section-body"><el-input v-model="search" placeholder="搜索用户名" clearable class="user-search" @input="userPage=1" /><el-table :data="paged"><el-table-column prop="username" label="用户" min-width="150" /><el-table-column label="状态" width="90"><template #default="{row}">{{!row.enabled?'已禁用':row.expires_at&&new Date(row.expires_at).getTime()<=Date.now()?'已到期':'已启用'}}</template></el-table-column><el-table-column label="余额 / 元" width="120"><template #default="{row}">{{yuan(row.balance_cents||0)}}</template></el-table-column><el-table-column prop="plan_name" label="套餐" min-width="160" /><el-table-column label="每节点限速" width="140"><template #default="{row}">{{row.plan_id?limitText(row.speed_mbps,'Mbps'):'—'}}</template></el-table-column><el-table-column label="流量 / 额度" min-width="200"><template #default="{row}">{{bytes(row.traffic_bytes)}} / {{row.plan_id?quotaText(row.quota_bytes):'未分配套餐'}}</template></el-table-column><el-table-column label="规则上限" width="100"><template #default="{row}">{{row.plan_id?limitText(row.max_rules):'—'}}</template></el-table-column><el-table-column label="操作" width="240"><template #default="{row}"><div class="user-row-actions"><el-button link type="primary" @click="edit(row)">编辑</el-button><el-button link type="primary" @click="credit(row)">充值</el-button><a class="text-link" :href="`/admin/users/${row.id}/forward_rules`">管理规则 ({{row.rule_count}})</a></div></template></el-table-column></el-table><el-pagination v-model:current-page="userPage" :page-size="25" :total="filtered.length" layout="prev, pager, next, total" class="user-pagination" /></div></section>
 <el-dialog v-model="dialog" :title="editID?'编辑用户':'创建用户'" width="680px" top="4vh" class="managed-form-dialog"><el-form label-position="top">
  <el-form-item label="用户名"><el-input v-model="form.username" /></el-form-item><el-form-item :label="editID?'新密码（留空不修改）':'密码（至少 12 字节）'"><el-input v-model="form.password" type="password" show-password /></el-form-item>
  <el-form-item label="套餐"><el-select :model-value="form.plan_id" @update:model-value="selectPlan($event)" filterable><el-option label="未分配套餐" :value="0" /><el-option v-for="p in plans" :key="p.id" :label="p.name+(p.enabled?'':'（停用）')" :value="p.id" /></el-select><span class="field-tip">分配或更换套餐时复制初始设置，已有用户不随套餐修改。同套餐续费保留个人设置并重置已用流量。</span></el-form-item>
  <div class="form-section-title">个人资源设置</div><div class="form-grid">
   <el-form-item label="总流量额度"><LimitInput v-model="resource.quota_gib" unit="GiB" :sentinel="-1" :min="0" :max="1073741824" :precision="6" /></el-form-item>
   <el-form-item label="已用流量"><el-input v-model="resource.traffic_gib" inputmode="decimal"><template #append>GiB</template></el-input></el-form-item>
   <el-form-item label="每节点用户限速"><LimitInput v-model="resource.speed_mbps" unit="Mbps" :max="100000" /></el-form-item>
   <el-form-item label="规则数量上限"><LimitInput v-model="resource.max_rules" unit="条" :max="10000" /></el-form-item>
   <el-form-item label="每节点连接数上限"><LimitInput v-model="resource.max_connections" unit="条" :max="1000000" /></el-form-item>
   <el-form-item label="每节点活跃 IP 上限"><LimitInput v-model="resource.ip_limit" unit="个" :max="1000000" /></el-form-item>
  </div><p class="field-tip">限制留空表示不限制，流量填 0 表示零额度。已用流量按双向数据合计；修改后按新值继续累计，历史统计保留。</p>
  <div class="form-section-title">每条规则的限制</div><div class="form-grid">
   <el-form-item label="规则合计限速"><LimitInput v-model="resource.rule_speed_mbps" unit="Mbps" :max="100000" /></el-form-item>
   <el-form-item label="规则活跃 IP 上限"><LimitInput v-model="resource.rule_ip_limit" unit="个" :max="1000000" /></el-form-item>
   <el-form-item label="规则连接数上限"><LimitInput v-model="resource.rule_connection_limit" unit="条" :max="1000000" /></el-form-item>
  </div>
  <el-form-item label="允许使用的节点组"><el-select v-model="resource.node_group_ids" multiple filterable placeholder="未选择时无节点权限"><el-option v-for="g in nodeGroups" :key="g.id" :label="g.name+(g.enabled?'':'（停用）')" :value="g.id" /></el-select></el-form-item>
  <el-form-item label="到期时间"><el-date-picker :model-value="resource.expires_at" @update:model-value="resource.expires_at=$event||''" type="datetime" value-format="YYYY-MM-DDTHH:mm:ssZ" placeholder="留空则永不到期" /></el-form-item>
  <el-form-item label="启用账号"><el-switch v-model="form.enabled" /></el-form-item>
 </el-form><template #footer><el-button @click="dialog=false">取消</el-button><el-button type="primary" :loading="busy" @click="save">保存用户</el-button></template></el-dialog>
<el-dialog v-model="rechargeDialog" title="管理员充值余额" width="500px"><p>{{rechargeUser?.username}} · 当前余额 {{yuan(rechargeUser?.balance_cents||0)}} 元</p><el-form label-position="top"><el-form-item label="充值金额 / 元"><el-input v-model="recharge.amount" inputmode="decimal" /></el-form-item><el-form-item label="充值备注"><el-input v-model="recharge.note" type="textarea" :rows="2" maxlength="300" placeholder="填写充值原因或线下收款说明" /></el-form-item></el-form><p class="field-tip">确认后立即增加余额，并记录操作管理员、金额和备注。</p><template #footer><el-button @click="rechargeDialog=false">取消</el-button><el-button type="primary" :loading="busy" @click="saveCredit">确认充值</el-button></template></el-dialog></PageShell></template>
