<script setup lang="ts">
import {reactive,ref} from 'vue'
import {ElMessage} from 'element-plus'
import PageShell from '../PageShell.vue'
import {usePage} from '../page'
import {api} from '../api'
import NodeConnectionFields from '../NodeConnectionFields.vue'
import NodeProtocolsDialog from '../NodeProtocolsDialog.vue'
import NodeSecurityDialog from '../NodeSecurityDialog.vue'
import {nodeTLSConfig,protocolDefaults,applyNodeTransport,applyNodeSecurity,type NodeProtocolsInput,type NodeSecurityInput,type NodeTransportInput} from '../node-protocol'
type Choice={id:number;name:string;ingress_enabled:boolean}
type Details={node_id:number;node_name:string;config:NodeProtocolsInput;ingress_nodes:Choice[]}
const editID=Number(location.pathname.match(/^\/admin\/nodes\/([1-9]\d*)\/protocols$/)?.[1]||0)
const details=ref<Details|null>(null),nodes=ref<Choice[]>([]),busy=ref(false),protocolDialog=ref(false),securityDialog=ref(false)
const nodeForm=reactive(protocolDefaults())
async function load(){
 if(!editID)throw Error('节点地址无效')
 details.value=await api<Details>(`admin/nodes/${editID}/protocols`)
 Object.assign(nodeForm,details.value.config)
 nodeForm.tls=nodeTLSConfig(details.value.config.tls)
 nodeForm.allowed_ingress_ids=[...details.value.config.allowed_ingress_ids]
 nodes.value=details.value.ingress_nodes
}
const {me,loading,error}=usePage(load,{admin:true})
async function save(){
 busy.value=true
 try{await api(`admin/nodes/${editID}/protocols`,'PUT',nodeForm);await load();ElMessage.success('入口、出口与传输协议配置已保存并下发')}catch(e){ElMessage.error((e as Error).message)}finally{busy.value=false}
}
function protocolsSaved(config:NodeTransportInput){applyNodeTransport(nodeForm,config)}
function securitySaved(config:NodeSecurityInput){applyNodeSecurity(nodeForm,config)}
</script>
<template>
 <PageShell :me="me" :loading="loading" :error="error" active="nodes" admin>
  <div class="managed-rules-heading">
    <a class="back-link" href="/admin/nodes">← 返回节点管理</a>
    <span>{{details?.node_name}} · 节点连接配置</span>
    </div>
  <nav class="admin-resource-tabs">
    <a href="/admin/nodes">节点管理</a>
    <a :href="`/admin/nodes/${editID}/protocols`" class="active">连接配置</a>
    <a :href="`/admin/nodes/${editID}/ddns`">DDNS</a>
    </nav>
  <section class="surface">
    <div class="section-header">
    <strong>节点连接配置</strong>
    <el-button type="primary" :loading="busy" @click="save">保存并下发</el-button>
    </div>
    <div class="section-body settings-form">
<el-form label-position="top" @submit.prevent="save">
 <NodeConnectionFields :form="nodeForm" :nodes="nodes" :nodeID="editID" @edit-transport="protocolDialog=true" @edit-security="securityDialog=true"/>
</el-form>
  <el-button type="primary" :loading="busy" @click="save">保存并下发</el-button>
  </div>
    </section>
 <NodeSecurityDialog v-model="securityDialog" :initial="nodeForm" @saved="securitySaved"/>
 <NodeProtocolsDialog v-model="protocolDialog" :initial="nodeForm" @saved="protocolsSaved"/>
 </PageShell>
</template>
