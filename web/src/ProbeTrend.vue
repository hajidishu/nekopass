<script setup lang="ts">
import {computed} from 'vue'
import type {ProbeHistoryPoint} from './api'
import {probePath,probeScale,type ProbeSeries} from './probe-chart'
const props=withDefaults(defineProps<{points:ProbeHistoryPoint[];series:ProbeSeries[];label:string;percentage?:boolean;error?:string}>(),{percentage:false,error:''})
const scale=computed(()=>probeScale(props.points,props.series.map(s=>s.key),props.percentage))
const curves=computed(()=>props.series.map(series=>({...series,...probePath(props.points,series.key,scale.value,props.percentage?40:76)})))
const anyData=computed(()=>curves.value.some(c=>c.line))
const span=computed(()=>curves.value[0]?.span||60)
function tick(value:number){
 if(props.percentage)return `${Math.round(value)}%`
 const divisor=scale.value>=1e9?1e9:1e6
 return `${(value/divisor).toFixed(scale.value<1e6?3:2)} ${divisor===1e9?'GB/s':'MB/s'}`
}
</script>
<template>
 <div class="probe-trend" :data-testid="`probe-chart-${label}`">
  <svg viewBox="0 0 320 100" role="img" :aria-label="`${label}趋势图`">
   <g v-for="ratio in [0,.5,1]" :key="ratio"><line :x1="percentage?40:76" x2="310" :y1="78-ratio*70" :y2="78-ratio*70" class="probe-chart-grid"/><text x="0" :y="81-ratio*70">{{tick(scale*ratio)}}</text></g>
   <g v-for="curve in curves" :key="curve.key">
    <path v-if="percentage&&curve.area" :d="curve.area" :fill="curve.color" fill-opacity=".12"/>
    <path v-if="curve.line" :data-series="curve.key" :d="curve.line" fill="none" :stroke="curve.color" stroke-width="1.7" stroke-linejoin="round"/>
    <circle v-if="curve.last" :cx="curve.last[0]" :cy="curve.last[1]" r="1.8" :fill="curve.color"/>
   </g>
   <text v-if="!anyData" x="175" y="44" text-anchor="middle">等待采样</text>
   <text :x="percentage?40:76" y="97">{{Math.round(span)}} 秒前</text><text x="310" y="97" text-anchor="end">最近采样</text>
  </svg>
  <span v-if="error" class="probe-trend-error" :title="error">历史暂不可用，显示当前采样</span>
 </div>
</template>
