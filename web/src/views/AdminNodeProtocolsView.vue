<script setup lang="ts">
import {reactive,ref} from 'vue'
import {ElMessage} from 'element-plus'
import PageShell from '../PageShell.vue'
import {usePage} from '../page'
import {api} from '../api'
import NodeProtocolsForm from '../NodeProtocolsForm.vue'
import {nodeTLSDefaults,protocolDefaults,type NodeProtocolsInput} from '../node-protocol'
type Choice={id:number;name:string;ingress_enabled:boolean}
type Details={node_id:number;node_name:string;config:NodeProtocolsInput;ingress_nodes:Choice[]}
const editID=Number(location.pathname.match(/^\/admin\/nodes\/([1-9]\d*)\/protocols$/)?.[1]||0)
const details=ref<Details|null>(null),nodes=ref<Choice[]>([]),busy=ref(false),dnsJSON=ref('{}')
const nodeForm=reactive(protocolDefaults())
async function load(){
 if(!editID)throw Error('节点地址无效')
 details.value=await api<Details>(`admin/nodes/${editID}/protocols`)
 Object.assign(nodeForm,details.value.config)
 nodeForm.tls={...nodeTLSDefaults(),...(details.value.config.tls||{})}
 nodeForm.allowed_ingress_ids=[...details.value.config.allowed_ingress_ids]
 nodes.value=details.value.ingress_nodes
 dnsJSON.value=JSON.stringify(nodeForm.tls.dns_credentials||{},null,2)
}
const {me,loading,error}=usePage(load,{admin:true})
async function save(){
 let credentials=nodeForm.tls.dns_credentials
 if(nodeForm.tunnel_security==='tls'&&nodeForm.tls.certificate_mode==='acme_dns'){
  try{credentials=JSON.parse(dnsJSON.value);if(!credentials||typeof credentials!=='object'||Array.isArray(credentials))throw Error()}catch{ElMessage.error('DNS 凭据须为 JSON 对象');return}
 }
 busy.value=true
 try{nodeForm.tls.dns_credentials=credentials;await api(`admin/nodes/${editID}/protocols`,'PUT',nodeForm);await load();ElMessage.success('入口、出口与传输协议配置已保存并下发')}catch(e){ElMessage.error((e as Error).message)}finally{busy.value=false}
}
</script>
<template>
 <PageShell :me="me" :loading="loading" :error="error" active="nodes" admin>
  <div class="managed-rules-heading">
    <a class="back-link" href="/admin/nodes">← 返回节点管理</a>
    <span>{{details?.node_name}} · 传输协议</span>
    </div>
  <nav class="admin-resource-tabs">
    <a href="/admin/nodes">节点管理</a>
    <a :href="`/admin/nodes/${editID}/protocols`" class="active">传输协议</a>
    <a :href="`/admin/nodes/${editID}/ddns`">DDNS</a>
    </nav>
  <section class="surface">
    <div class="section-header">
    <strong>入口、出口与传输协议</strong>
    <el-button type="primary" :loading="busy" @click="save">保存并下发</el-button>
    </div>
    <div class="section-body settings-form">
<NodeProtocolsForm :form="nodeForm" :nodes="nodes" :nodeID="editID" v-model:dnsJSON="dnsJSON" @submit="save" />
  <el-button type="primary" :loading="busy" @click="save">保存并下发</el-button>
  </div>
    </section>
 </PageShell>
</template>
