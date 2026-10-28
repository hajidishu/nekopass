<script setup lang="ts">
import {computed} from 'vue'
import type {ProbeHistoryPoint} from './api'
import ProbeTrend from './ProbeTrend.vue'
const props=defineProps<{points:ProbeHistoryPoint[];kind:'cpu'|'memory'|'disk';label:string;value:number;ready:boolean;detail?:string;error?:string}>()
const accent=computed(()=>({cpu:'#77b6ff',memory:'#b69bff',disk:'#65d8b0'})[props.kind])
const series=computed(()=>[{key:props.kind,label:props.label,color:accent.value}])
</script>
<template>
 <div class="probe-meter">
  <div class="probe-meter-heading"><span>{{label}}</span><strong :style="{color:accent}">{{ready?value.toFixed(2)+'%':'—'}}</strong></div>
  <ProbeTrend :points="points" :series="series" :label="kind" percentage :error="error"/>
  <small v-if="detail">{{detail}}</small>
 </div>
</template>
