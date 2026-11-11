<script setup lang="ts">
import {computed} from 'vue'
import {dashboardSpark} from './dashboard-chart'
const props=withDefaults(defineProps<{values:ReadonlyArray<number|null>;color?:string;percentage?:boolean;label?:string}>(),{color:'var(--el-color-primary)',percentage:false,label:'最近采样趋势'})
const plot=computed(()=>dashboardSpark(props.values,props.percentage))
</script>
<template><svg class="dashboard-spark" viewBox="0 0 80 30" role="img" :aria-label="label"><path v-if="plot.line" :d="plot.line" fill="none" :stroke="color" stroke-width="1.6" stroke-linejoin="round"/><circle v-if="plot.last" :cx="plot.last[0]" :cy="plot.last[1]" r="1.6" :fill="color"/></svg></template>
<style scoped>.dashboard-spark{display:block;width:80px;height:30px;flex-shrink:0;overflow:visible}</style>
