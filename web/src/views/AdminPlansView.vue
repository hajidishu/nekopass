<script setup lang="ts">
import {ref} from 'vue'
import PageShell from '../PageShell.vue'
import PlansPage from '../PlansPage.vue'
import {usePage} from '../page'
import {api,type Plan,type NodeGroup} from '../api'
const plans=ref<Plan[]>([]),groups=ref<NodeGroup[]>([])
const {me,loading,error,refresh}=usePage(async()=>{const[p,g]=await Promise.all([api<Plan[]>('admin/plans'),api<NodeGroup[]>('admin/node-groups')]);plans.value=p;groups.value=g},{admin:true,interval:5000})
</script>
<template><PageShell :me="me" :loading="loading" :error="error" active="plans" admin><PlansPage :plans="plans" :groups="groups" @refresh="refresh" /></PageShell></template>
