<script setup lang="ts">
import {ref} from 'vue'
import PageShell from '../PageShell.vue'
import ProbePage from '../ProbePage.vue'
import {usePage} from '../page'
import {api,type ProbeNode} from '../api'
const nodes=ref<ProbeNode[]>([])
const {me,loading,error}=usePage(async()=>{nodes.value=await api<ProbeNode[]>('node-status')},{interval:5000})
</script>
<template><PageShell :me="me" :loading="loading" :error="error" active="probe"><ProbePage :nodes="nodes" /></PageShell></template>
