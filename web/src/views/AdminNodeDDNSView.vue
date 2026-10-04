<script setup lang="ts">
import { reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import PageShell from '../PageShell.vue'
import { usePage } from '../page'
import { api } from '../api'
type Config={enabled:boolean;provider:string;record_name:string;zone_id:string;token:string;ipv4:boolean;ipv6:boolean;interval_seconds:number;ttl:number;ipv4_url:string;ipv6_url:string;use_for_ingress:boolean;use_for_egress:boolean}
type Status={generation?:number;state?:string;ipv4?:string;ipv6?:string;checked_unix?:number;updated_unix?:number;error?:string}
type Details={node_id:number;node_name:string;protocol_version:number;online:boolean;config:Config;generation:number;status:Status;status_received_at:string|null}
const id=location.pathname.match(/^\/admin\/nodes\/([1-9]\d*)\/ddns$/)?.[1]
const data=ref<Details|null>(null),busy=ref(false),initialized=ref(false)
const form=reactive<Config>({enabled:false,provider:'cloudflare',record_name:'',zone_id:'',token:'',ipv4:true,ipv6:false,interval_seconds:300,ttl:300,ipv4_url:'https://api.ipify.org',ipv6_url:'https://api6.ipify.org',use_for_ingress:true,use_for_egress:true})
const {me,loading,error,refresh}=usePage(async()=>{if(!id)throw Error('节点地址无效');data.value=await api<Details>(`admin/nodes/${id}/ddns`);if(!initialized.value){Object.assign(form,data.value.config);initialized.value=true}},{admin:true,interval:5000})
const states:Record<string,string>={disabled:'已关闭',pending:'等待节点更新',ok:'已同步',error:'更新失败',partial:'部分同步'}
const time=(unix?:number)=>unix?new Date(unix*1000).toLocaleString():'—'
async function save(){busy.value=true;try{await api(`admin/nodes/${id}/ddns`,'PUT',form);await refresh();ElMessage.success('DDNS 配置已保存并下发')}catch(e){ElMessage.error((e as Error).message)}finally{busy.value=false}}
async function update(){busy.value=true;try{await api(`admin/nodes/${id}/ddns/run`,'POST',{});await refresh();ElMessage.success('已通知节点立即检查')}catch(e){ElMessage.error((e as Error).message)}finally{busy.value=false}}
</script>
<template>
 <PageShell :me="me" :loading="loading" :error="error" active="nodes" admin>
  <div class="managed-rules-heading"><a class="back-link" href="/admin/nodes">← 返回节点管理</a><span>{{data?.node_name}} · DDNS</span></div>
  <section class="surface"><div class="section-header"><strong>DDNS 设置</strong><el-button type="primary" :loading="busy" @click="save">保存并下发</el-button></div>
   <div class="section-body settings-form">
    <el-alert v-if="data && data.protocol_version<8" title="此节点需要升级到 Agent v0.9.0 或以上才能运行 DDNS。" type="warning" :closable="false"/>
    <el-form label-position="top" @submit.prevent="save">
     <el-form-item label="启用 DDNS"><el-switch v-model="form.enabled"/></el-form-item>
     <div class="form-grid"><el-form-item label="DNS 服务商"><el-select v-model="form.provider"><el-option label="Cloudflare" value="cloudflare"/></el-select></el-form-item><el-form-item label="记录域名"><el-input v-model="form.record_name" placeholder="node.example.com"/></el-form-item></div>
     <el-form-item label="Cloudflare API Token"><el-input v-model="form.token" type="password" show-password autocomplete="off" placeholder="对应区域的 DNS 编辑 Token"/></el-form-item>
     <el-form-item label="Zone ID"><el-input v-model="form.zone_id" placeholder="留空自动识别（需要 Zone 读取权限）"/></el-form-item>
     <el-form-item label="IP 类型"><el-checkbox v-model="form.ipv4">IPv4 / A</el-checkbox><el-checkbox v-model="form.ipv6">IPv6 / AAAA</el-checkbox></el-form-item>
     <div class="form-grid"><el-form-item label="检查间隔 / 秒"><el-input-number v-model="form.interval_seconds" :min="60" :max="86400"/></el-form-item><el-form-item label="DNS TTL / 秒"><el-input-number v-model="form.ttl" :min="1" :max="86400"/><span class="field-tip">1 为自动；其余为 60–86400。</span></el-form-item></div>
     <el-form-item v-if="form.ipv4" label="IPv4 获取地址"><el-input v-model="form.ipv4_url"/></el-form-item><el-form-item v-if="form.ipv6" label="IPv6 获取地址"><el-input v-model="form.ipv6_url"/></el-form-item>
     <el-form-item label="使用此域名"><el-checkbox v-model="form.use_for_ingress">节点公网地址</el-checkbox><el-checkbox v-model="form.use_for_egress">隧道出口地址</el-checkbox></el-form-item>
     <p class="field-tip">节点获取公网 IP 并更新记录，使用仅 DNS 模式；不存在时自动创建 A/AAAA 记录。</p>
    </el-form>
   </div>
  </section>
  <section class="surface"><div class="section-header"><strong>同步状态</strong><el-button :loading="busy" :disabled="!data?.config.enabled" @click="update">立即更新</el-button></div>
   <div class="section-body"><el-descriptions :column="2" border>
    <el-descriptions-item label="节点">{{data?.online?'在线':'离线'}}</el-descriptions-item><el-descriptions-item label="DDNS">{{states[data?.status.state||'disabled']}}</el-descriptions-item>
    <el-descriptions-item label="IPv4">{{data?.status.ipv4||'—'}}</el-descriptions-item><el-descriptions-item label="IPv6">{{data?.status.ipv6||'—'}}</el-descriptions-item>
    <el-descriptions-item label="最近检查">{{time(data?.status.checked_unix)}}</el-descriptions-item><el-descriptions-item label="最近变更">{{time(data?.status.updated_unix)}}</el-descriptions-item>
    <el-descriptions-item v-if="data?.status.error" label="反馈" :span="2">{{data.status.error}}</el-descriptions-item>
   </el-descriptions></div>
  </section>
 </PageShell>
</template>
