<script setup lang="ts">
import {reactive,watch} from 'vue'
import NodeProtocolsForm from './NodeProtocolsForm.vue'
import {nodeTLSConfig,nodeTransportInput,protocolDefaults,type NodeProtocolsInput,type NodeTransportInput} from './node-protocol'
const props=defineProps<{modelValue:boolean;initial:NodeProtocolsInput}>()
const emit=defineEmits<{'update:modelValue':[value:boolean];saved:[config:NodeTransportInput]}>()
const form=reactive(protocolDefaults())
watch(()=>props.modelValue,open=>{
 if(!open)return
 const copy=JSON.parse(JSON.stringify(props.initial))
 Object.assign(form,copy)
 form.tls=nodeTLSConfig(copy.tls)
})
function save(){emit('saved',nodeTransportInput(form));emit('update:modelValue',false)}
</script>
<template>
 <el-dialog :model-value="modelValue" @update:model-value="emit('update:modelValue',$event)" title="编辑传输协议" width="680px" top="8vh" append-to-body class="managed-form-dialog">
  <NodeProtocolsForm :form="form" @submit="save"/>
  <template #footer>
   <el-button @click="emit('update:modelValue',false)">取消</el-button>
   <el-button type="primary" @click="save">确定</el-button>
  </template>
 </el-dialog>
</template>
