<script setup lang="ts">
import {reactive,ref,watch} from 'vue'
import {ElMessage} from 'element-plus'
import NodeSecurityFields from './NodeSecurityFields.vue'
import {nodeTLSConfig,nodeDNSCredentials,nodeSecurityInput,protocolDefaults,type NodeProtocolsInput,type NodeSecurityInput} from './node-protocol'
const props=defineProps<{modelValue:boolean;initial:NodeProtocolsInput}>()
const emit=defineEmits<{'update:modelValue':[value:boolean];saved:[config:NodeSecurityInput]}>()
const form=reactive(protocolDefaults()),dnsJSON=ref('{}')
watch(()=>props.modelValue,open=>{
 if(!open)return
 const copy=JSON.parse(JSON.stringify(props.initial))
 Object.assign(form,copy)
 form.tls=nodeTLSConfig(copy.tls)
 form.random={cipher:'chacha20-poly1305',key:'',...copy.random}
 dnsJSON.value=JSON.stringify(form.tls.dns_credentials||{},null,2)
})
function save(){
 try{form.tls.dns_credentials=nodeDNSCredentials(form,dnsJSON.value)}catch{ElMessage.error('DNS 凭据须为 JSON 对象');return}
 emit('saved',nodeSecurityInput(form));emit('update:modelValue',false)
}
</script>
<template>
 <el-dialog :model-value="modelValue" @update:model-value="emit('update:modelValue',$event)" title="安全性设置" width="760px" top="4vh" append-to-body class="managed-form-dialog">
  <el-form label-position="top" @submit.prevent="save"><NodeSecurityFields :form="form" v-model:dnsJSON="dnsJSON"/></el-form>
  <template #footer>
   <el-button @click="emit('update:modelValue',false)">取消</el-button>
   <el-button type="primary" @click="save">确定</el-button>
  </template>
 </el-dialog>
</template>
