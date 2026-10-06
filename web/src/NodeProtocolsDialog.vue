<script setup lang="ts">
import {reactive,ref,watch} from 'vue'
import {ElMessage} from 'element-plus'
import {api,type Node} from './api'
import NodeProtocolsForm from './NodeProtocolsForm.vue'
import {nodeTLSDefaults,protocolDefaults,type NodeProtocolsInput} from './node-protocol'

type Choice={id:number;name:string;ingress_enabled:boolean}
type Details={config:NodeProtocolsInput;ingress_nodes:Choice[]}
const props=defineProps<{modelValue:boolean;nodeID:number;initial:NodeProtocolsInput;nodes:Node[]}>()
const emit=defineEmits<{ 'update:modelValue':[value:boolean];saved:[config:NodeProtocolsInput] }>()
const form=reactive(protocolDefaults()),nodes=ref<Choice[]>([]),dnsJSON=ref('{}'),loading=ref(false),saving=ref(false),error=ref('')
let generation=0
function setOpen(value:boolean){emit('update:modelValue',value)}
function setForm(config:NodeProtocolsInput){
 const copy=JSON.parse(JSON.stringify(config))
 Object.assign(form,Object.fromEntries(Object.keys(protocolDefaults()).map(key=>[key,copy[key]])))
 form.tls={...nodeTLSDefaults(),...(form.tls||{})}
 form.allowed_ingress_ids=[...(form.allowed_ingress_ids||[])]
 dnsJSON.value=JSON.stringify(form.tls.dns_credentials||{},null,2)
}
watch(()=>props.modelValue,async open=>{
 const current=++generation
 if(!open)return
 error.value='';loading.value=true
 try{
  if(props.nodeID){const data=await api<Details>(`admin/nodes/${props.nodeID}/protocols`);if(current!==generation)return;setForm(data.config);nodes.value=data.ingress_nodes}
  else{setForm(props.initial);nodes.value=props.nodes.filter(n=>n.ingress_enabled).map(n=>({id:n.id,name:n.name,ingress_enabled:true}))}
 }catch(e){if(current===generation)error.value=(e as Error).message}
 finally{if(current===generation)loading.value=false}
})
async function save(){
 let credentials:Record<string,string>
 try{credentials=JSON.parse(dnsJSON.value);if(!credentials||typeof credentials!=='object'||Array.isArray(credentials))throw Error()}catch{ElMessage.error('DNS 凭据须为 JSON 对象');return}
 saving.value=true
 try{
  form.tls.dns_credentials=credentials
  const config:NodeProtocolsInput=JSON.parse(JSON.stringify(form))
  if(props.nodeID)await api(`admin/nodes/${props.nodeID}/protocols`,'PUT',config)
  emit('saved',config);emit('update:modelValue',false)
  if(props.nodeID)ElMessage.success('传输协议已保存并下发')
 }catch(e){ElMessage.error((e as Error).message)}finally{saving.value=false}
}
</script>
<template>
 <el-dialog :model-value="modelValue" @update:model-value="setOpen" title="编辑传输协议" width="760px" top="4vh" append-to-body class="managed-form-dialog" :close-on-click-modal="!saving" :close-on-press-escape="!saving" :show-close="!saving">
  <div v-loading="loading">
   <el-alert v-if="error" :title="error" type="error" :closable="false" />
   <NodeProtocolsForm v-if="!loading&&!error" :form="form" :nodes="nodes" :nodeID="nodeID" v-model:dnsJSON="dnsJSON" @submit="save" />
  </div>
  <template #footer>
   <el-button :disabled="saving" @click="emit('update:modelValue',false)">取消</el-button>
   <el-button type="primary" :loading="saving" :disabled="loading||!!error" @click="save">{{nodeID?'保存并下发':'确定'}}</el-button>
  </template>
 </el-dialog>
</template>
