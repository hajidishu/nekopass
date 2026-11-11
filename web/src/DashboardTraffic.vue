<script setup lang="ts">
import {computed,onMounted,onUnmounted,ref} from 'vue'
import {bytes} from './api'
import {trafficPlot,type DashboardPeriod,type TrafficPoint} from './dashboard-chart'
const props=defineProps<{points:TrafficPoint[];period:DashboardPeriod;unit:'mbps'|'bytes';at:number}>()
const container=ref<HTMLElement>(),width=ref(800),selected=ref<number|null>(null)
let observer:ResizeObserver|undefined
onMounted(()=>{observer=new ResizeObserver(entries=>{width.value=Math.max(260,entries[0]?.contentRect.width||800)});if(container.value)observer.observe(container.value)})
onUnmounted(()=>observer?.disconnect())
const plot=computed(()=>trafficPlot(props.points,props.period,props.at,width.value))
const hover=computed(()=>selected.value==null?null:plot.value.visible.find(p=>p.at===selected.value)||null)
function time(at:number,full=false){return new Intl.DateTimeFormat('zh-CN',{timeZone:'Asia/Shanghai',...(props.period==='24h'?{hour:'2-digit',minute:'2-digit',...(full?{month:'2-digit',day:'2-digit'}:{})}:{month:'2-digit',day:'2-digit'})}).format(new Date(at*1000))}
function amount(value:number|null){if(value==null||!Number.isFinite(value))return '暂无采样';return props.unit==='bytes'?bytes(value):`${value.toLocaleString('zh-CN',{maximumFractionDigits:2})} Mbps`}
function axis(value:number){if(props.unit==='bytes')return bytes(value);const divisor=plot.value.scale>=1000?1000:1;return `${(value/divisor).toLocaleString('zh-CN',{maximumFractionDigits:2})} ${divisor===1000?'Gbps':'Mbps'}`}
function move(e:PointerEvent){if(!plot.value.visible.length)return;const rect=(e.currentTarget as SVGElement).getBoundingClientRect(),x=(e.clientX-rect.left)/rect.width*width.value;selected.value=plot.value.visible.reduce((a,b)=>Math.abs(plot.value.x(b.at)-x)<Math.abs(plot.value.x(a.at)-x)?b:a).at}
function key(e:KeyboardEvent){if(e.key!=='ArrowLeft'&&e.key!=='ArrowRight')return;e.preventDefault();const data=plot.value.visible,index=data.findIndex(p=>p.at===selected.value);selected.value=data[Math.max(0,Math.min(data.length-1,index+(e.key==='ArrowLeft'?-1:1)))]?.at??null}
</script>
<template><div ref="container" class="dashboard-traffic-chart" data-testid="dashboard-traffic-chart">
 <svg :viewBox="`0 0 ${width} 220`" role="img" aria-label="全网上传下载流量趋势，可使用左右方向键查看采样" tabindex="0" @pointermove="move" @pointerleave="selected=null" @keydown="key" @blur="selected=null">
  <g v-for="ratio in [0,.25,.5,.75,1]" :key="ratio"><line :x1="plot.left" :x2="plot.right" :y1="plot.bottom-(plot.bottom-plot.top)*ratio" :y2="plot.bottom-(plot.bottom-plot.top)*ratio" class="dashboard-grid-line"/><text :x="plot.left-10" :y="plot.bottom-(plot.bottom-plot.top)*ratio+4" text-anchor="end">{{axis(plot.scale*ratio)}}</text></g>
  <g v-for="tick in plot.ticks" :key="tick.at"><line :x1="tick.x" :x2="tick.x" :y1="plot.top" :y2="plot.bottom" class="dashboard-grid-line vertical"/><text :x="tick.x" y="208" :text-anchor="tick.x===plot.left?'start':tick.x===plot.right?'end':'middle'">{{time(tick.at)}}</text></g>
  <g v-for="curve in plot.curves" :key="curve.key" :style="{color:curve.key==='rx'?'var(--dashboard-blue)':'var(--dashboard-mint)'}"><path v-if="curve.area" :d="curve.area" fill="currentColor" fill-opacity=".1"/><path v-if="curve.line" :d="curve.line" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" :data-series="curve.key"/><circle v-for="(dot,i) in curve.isolated" :key="i" :cx="dot[0]" :cy="dot[1]" r="2.6" fill="currentColor"/><circle v-if="curve.last" :cx="curve.last[0]" :cy="curve.last[1]" r="2.6" fill="currentColor"/></g>
  <line v-if="hover" :x1="plot.x(hover.at)" :x2="plot.x(hover.at)" :y1="plot.top" :y2="plot.bottom" class="dashboard-hover-line"/>
  <text v-if="!plot.hasData" :x="(plot.left+plot.right)/2" y="98" text-anchor="middle" class="dashboard-chart-empty">等待流量采样</text>
 </svg>
 <div v-if="hover" class="dashboard-chart-tooltip" :style="{left:`${Math.min(width-190,Math.max(0,plot.x(hover.at)+12))}px`}"><strong>{{time(hover.at,true)}}</strong><span><i class="rx"/>下载 {{amount(hover.rx)}}</span><span><i class="tx"/>上传 {{amount(hover.tx)}}</span></div>
 <div class="dashboard-chart-legend"><span><i class="rx"/>下载</span><span><i class="tx"/>上传</span><small>{{period==='24h'?'小时采样平均速率':'每日累计流量'}} · UTC+8</small></div>
</div></template>
<style scoped>
.dashboard-traffic-chart{position:relative;min-width:0;padding-top:6px}.dashboard-traffic-chart svg{display:block;width:100%;height:auto;min-height:170px;outline-offset:2px}.dashboard-traffic-chart text{fill:var(--muted);font-size:11px;font-family:inherit}.dashboard-grid-line{stroke:var(--border);stroke-dasharray:3 4;stroke-width:.8}.dashboard-grid-line.vertical{opacity:.5}.dashboard-hover-line{stroke:var(--muted);stroke-dasharray:4 4;stroke-width:1}.dashboard-chart-empty{font-size:13px!important}.dashboard-chart-legend{display:flex;justify-content:center;align-items:center;gap:22px;font-size:12px;color:var(--muted);margin-top:4px;flex-wrap:wrap}.dashboard-chart-legend>span{display:flex;align-items:center;gap:7px}.dashboard-chart-legend small{font-size:11px}.dashboard-chart-legend i,.dashboard-chart-tooltip i{display:inline-block;width:18px;height:2px}.rx{background:var(--dashboard-blue)}.tx{background:var(--dashboard-mint)}.dashboard-chart-tooltip{position:absolute;top:18px;display:grid;gap:7px;padding:12px 14px;background:var(--el-bg-color-overlay,var(--surface));border:1px solid var(--border);border-radius:8px;box-shadow:0 6px 20px #0002;pointer-events:none;z-index:2;font-size:12px;min-width:172px}.dashboard-chart-tooltip>span{display:flex;align-items:center;gap:6px}
</style>
