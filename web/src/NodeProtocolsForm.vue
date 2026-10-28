<script setup lang="ts">
import {toRefs,watch} from 'vue'
import type {NodeProtocolsInput} from './node-protocol'
const props=defineProps<{form:NodeProtocolsInput}>()
const {form:nodeForm}=toRefs(props)
defineEmits<{submit:[]}>()
watch(()=>nodeForm.value.tunnel_transport,value=>{if(value==='h3')nodeForm.value.tunnel_security='tls'})
</script>
<template>
 <el-form label-position="top" data-testid="node-transport-form" @submit.prevent="$emit('submit')">
  <el-form-item label="传输协议">
   <el-select v-model="nodeForm.tunnel_transport">
    <el-option label="raw(tcp)" value="raw_tcp"/>
    <el-option label="h2" value="h2"/><el-option label="HTTP/3" value="h3"/>
    <el-option label="raw(udp)" value="raw_udp"/>
   </el-select>
  </el-form-item>
  <p v-if="nodeForm.tunnel_transport==='h3'" class="field-tip">HTTP/3 固定使用 TLS 1.3，出口同一端口提供 TCP HTTPS 与 UDP HTTP/3。TCP 使用 CONNECT；UDP 使用 CONNECT-UDP。</p>
  <p v-if="nodeForm.tunnel_transport==='raw_udp'" class="field-tip">raw(udp) 仅承载 UDP 转发。</p>
  <template v-if="['h2','h3'].includes(nodeForm.tunnel_transport)">
   <div class="form-section-title">{{nodeForm.tunnel_transport==='h3'?'HTTP/3 参数':'HTTP/2 参数'}}</div>
   <div class="form-grid">
    <el-form-item :label="nodeForm.tunnel_transport==='h3'?'UDP 路径前缀':'HTTP Path'"><el-input v-model="nodeForm.tls.path"/></el-form-item>
    <el-form-item :label="nodeForm.tunnel_transport==='h3'?'UDP HTTP Host':'HTTP Host'"><el-input v-model="nodeForm.tls.host" placeholder="留空使用出口域名或地址"/></el-form-item>
    <el-form-item label="连接池上限"><el-input-number v-model="nodeForm.tls.pool_size" :min="1" :max="8"/></el-form-item>
    <el-form-item label="每流接收窗口 / MiB"><el-input-number v-model="nodeForm.tls.stream_window_mib" :min="1" :max="64"/></el-form-item>
    <el-form-item label="每连接接收窗口 / MiB"><el-input-number v-model="nodeForm.tls.connection_window_mib" :min="nodeForm.tls.stream_window_mib" :max="256"/></el-form-item>
    <el-form-item label="每连接并发流"><el-input-number v-model="nodeForm.tls.max_streams" :min="1" :max="1024"/></el-form-item>
   </div>
  </template>
 </el-form>
</template>
