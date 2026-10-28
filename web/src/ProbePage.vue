<script setup lang="ts">
import {computed,onBeforeUnmount,ref} from 'vue'
import {bytes,type ProbeNode,type Probe} from './api'
import Icon from './Icon.vue'
import ProbeMetric from './ProbeMetric.vue'
import ProbeTrend from './ProbeTrend.vue'
import {useProbeHistory} from './use-probe-history'
import type {ProbeSeries} from './probe-chart'
const props=defineProps<{nodes:ProbeNode[]}>()
const {histories,errors}=useProbeHistory(()=>props.nodes)
const ioSeries:ProbeSeries[]=[{key:'disk_read',label:'读取',color:'#77b6ff'},{key:'disk_write',label:'写入',color:'#bd9bff'}]
const now=ref(Date.now()),clock=setInterval(()=>{now.value=Date.now()},1000)
onBeforeUnmount(()=>clearInterval(clock))
const grouped=computed(()=>{const map=new Map<number,{id:number;name:string;nodes:ProbeNode[]}>();for(const n of props.nodes){if(!map.has(n.group_id))map.set(n.group_id,{id:n.group_id,name:n.group_name,nodes:[]});map.get(n.group_id)!.nodes.push(n)}return [...map.values()]})
function ready(n:ProbeNode,flag:keyof Probe){return n.online&&n.enabled&&!!n.metrics?.[flag]}
function percent(used?:number,total?:number){return total?Math.max(0,Math.min(100,Number(used||0)/total*100)):0}
function decimal(n?:number){return Number(n||0).toFixed(2)}
function io(n?:number){return Number(n||0)>=1e9?`${decimal(Number(n)/1e9)} GB/s`:`${decimal(Number(n||0)/1e6)} MB/s`}
function stamp(value?:string|null){return value?new Date(value).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false}):'—'}
function uptime(n:ProbeNode){
 if(!n.uptime_ready)return '—'
 const age=n.online&&n.updated_at?Math.max(0,Math.floor((now.value-Date.parse(n.updated_at))/1000)):0
 const seconds=Number(n.uptime_seconds||0)+age,pad=(v:number)=>String(v).padStart(2,'0')
 return `${Math.floor(seconds/86400)} 天 ${pad(Math.floor(seconds%86400/3600))}:${pad(Math.floor(seconds%3600/60))}:${pad(seconds%60)}`
}
function traffic(n:ProbeNode,value?:number){return n.traffic_ready?bytes(Number(value||0)):'—'}
</script>
<template>
 <div class="probe-page">
  <div class="probe-page-heading"><div><h2>节点状态</h2><p class="subtle">查看节点运行状态与实时趋势</p></div><span class="probe-live"><span></span>自动更新</span></div>
  <el-empty v-if="!grouped.length" description="当前套餐暂无可查看的节点组"/>
  <section v-for="g in grouped" :key="g.id" class="probe-group">
   <div class="probe-group-heading"><Icon name="folder"/><h3>{{g.name}}</h3><span class="subtle">{{g.nodes.filter(n=>n.online&&n.enabled).length}} / {{g.nodes.length}} 在线</span></div>
   <div class="probe-grid"><article v-for="n in g.nodes" :key="n.id" class="surface probe-card" :data-node-id="n.id">
    <div class="probe-card-heading"><strong>{{n.name}}</strong><span :class="['probe-status',{online:n.online&&n.enabled}]">{{!n.enabled?'维护中':n.online?'在线':'离线'}}</span></div>
    <div class="probe-bars">
     <ProbeMetric :points="histories.get(n.id)||[]" :error="errors.get(n.id)" kind="cpu" label="CPU" :value="Number(n.metrics?.cpu_percent||0)" :ready="ready(n,'cpu_ready')"/>
     <ProbeMetric :points="histories.get(n.id)||[]" :error="errors.get(n.id)" kind="memory" label="内存" :value="percent(n.metrics?.memory_used,n.metrics?.memory_total)" :ready="ready(n,'memory_ready')" :detail="ready(n,'memory_ready')?bytes(n.metrics?.memory_used||0)+' / '+bytes(n.metrics?.memory_total||0):'等待采样'"/>
     <ProbeMetric :points="histories.get(n.id)||[]" :error="errors.get(n.id)" kind="disk" label="硬盘" :value="percent(n.metrics?.disk_used,n.metrics?.disk_total)" :ready="ready(n,'disk_ready')" :detail="ready(n,'disk_ready')?bytes(n.metrics?.disk_used||0)+' / '+bytes(n.metrics?.disk_total||0):'等待采样'"/>
    </div>
    <div class="probe-network"><div><span>↓ 下载</span><strong>{{ready(n,'network_ready')?decimal(n.metrics?.rx_mbps):'—'}} <small>Mbps</small></strong></div><div><span>↑ 上传</span><strong>{{ready(n,'network_ready')?decimal(n.metrics?.tx_mbps):'—'}} <small>Mbps</small></strong></div></div>
    <div class="probe-traffic" data-testid="probe-traffic">
     <span></span><span>↑ 上传</span><span>↓ 下载</span>
     <span>今日</span><strong>{{traffic(n,n.traffic_today_tx_bytes)}}</strong><strong>{{traffic(n,n.traffic_today_rx_bytes)}}</strong>
     <span>近 30 天</span><strong>{{traffic(n,n.traffic_30d_tx_bytes)}}</strong><strong>{{traffic(n,n.traffic_30d_rx_bytes)}}</strong>
    </div>
    <div class="probe-io"><div class="probe-io-heading"><span>主磁盘 I/O</span><small>{{n.metrics?.disk_device||''}}</small></div><div class="probe-io-legend"><span class="probe-io-read">读 <strong>{{ready(n,'disk_io_ready')?io(n.metrics?.disk_read_bytes_per_second):'—'}}</strong></span><span class="probe-io-write">写 <strong>{{ready(n,'disk_io_ready')?io(n.metrics?.disk_write_bytes_per_second):'—'}}</strong></span></div><ProbeTrend :points="histories.get(n.id)||[]" :series="ioSeries" label="io" :error="errors.get(n.id)"/></div>
    <div class="probe-bottom"><div><span>网络连接数</span><strong>{{ready(n,'connections_ready')?Number(n.metrics?.tcp_connections||0)+Number(n.metrics?.udp_sockets||0):'—'}}</strong><small>{{ready(n,'connections_ready')?`TCP ${n.metrics?.tcp_connections||0} · UDP ${n.metrics?.udp_sockets||0}`:'暂无数据'}}</small></div><div><span>服务器负载</span><strong>{{ready(n,'load_ready')?decimal(n.metrics?.load1):'—'}}</strong><small>{{ready(n,'load_ready')?`${decimal(n.metrics?.load1)} / ${decimal(n.metrics?.load5)} / ${decimal(n.metrics?.load15)}`:'暂无数据'}}</small></div></div>
    <dl class="probe-times"><div><dt>已运行</dt><dd>{{uptime(n)}}</dd></div><div><dt>最后上报</dt><dd>{{stamp(n.last_report_at)}}</dd></div><div><dt>首次上线</dt><dd>{{stamp(n.first_connected_at)}}</dd></div></dl>
    <div class="probe-timezone">统计与时间：UTC+8</div>
   </article></div>
  </section>
 </div>
</template>
