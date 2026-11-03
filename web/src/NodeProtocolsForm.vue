<script setup lang="ts">
import {toRefs,watch,computed} from 'vue'
import type {NodeProtocolsInput} from './node-protocol'
const props=defineProps<{form:NodeProtocolsInput}>()
const {form:nodeForm}=toRefs(props)
const muxConnections=computed({get:()=>nodeForm.value.mux.max_connections||'',set:(v:string|number)=>{nodeForm.value.mux.max_connections=v===''?0:Number(v)}})
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
  <el-form-item v-if="['h3','raw_udp'].includes(nodeForm.tunnel_transport)" label="拥塞控制">
   <el-select v-model="nodeForm.brutal_enabled" data-testid="brutal-enabled"><el-option label="默认" :value="false"/><el-option label="Brutal" :value="true"/></el-select>
   <span class="field-tip">按入口、出口的节点带宽计算发送速率，多连接共享节点预算。</span>
  </el-form-item>
  <p v-if="nodeForm.tunnel_transport==='h3'" class="field-tip">HTTP/3 固定使用 TLS 1.3，出口同一端口提供 TCP HTTPS 与 UDP HTTP/3。TCP 使用 CONNECT；UDP 使用 CONNECT-UDP。</p>
  <p v-if="nodeForm.tunnel_transport==='raw_udp'" class="field-tip">raw(udp) 仅承载 UDP 转发。</p>
  <template v-if="['raw_tcp','raw_udp'].includes(nodeForm.tunnel_transport)">
   <div class="form-section-title">多路复用 Mux</div>
   <el-form-item label="启用 Mux"><el-switch v-model="nodeForm.mux.enabled" data-testid="mux-enabled"/><span class="field-tip switch-hint">多条业务连接或会话共享入口到出口的连接，入口和出口均需升级。</span></el-form-item>
   <div v-if="nodeForm.mux.enabled" class="form-grid" data-testid="mux-settings">
    <el-form-item label="每连接最大子会话数"><el-input-number v-model="nodeForm.mux.max_streams" :min="1" :max="4096" data-testid="mux-max-streams"/></el-form-item>
    <el-form-item label="底层连接数量上限"><el-input v-model="muxConnections" type="number" min="1" max="1024" placeholder="留空则不限制" data-testid="mux-max-connections"/></el-form-item>
    <el-form-item label="空闲回收时间"><el-input-number v-model="nodeForm.mux.idle_timeout_seconds" :min="10" :max="3600"/><span class="field-tip">秒</span></el-form-item>
   </div>
   <p v-if="nodeForm.tunnel_transport==='raw_udp'&&nodeForm.tunnel_security==='random'" class="field-tip">全随机 UDP 原有共享会话保持可用；启用 Mux 后可设置连接池和子会话上限。</p>
  </template>
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
