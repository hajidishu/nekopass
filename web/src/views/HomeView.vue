<script setup lang="ts">
import {ref} from 'vue'
import PageShell from '../PageShell.vue'
import {usePage} from '../page'
import {api} from '../api'
const content=ref('')
const {me,loading,error}=usePage(async()=>{content.value=(await api<{content:string}>('announcement')).content},{interval:5000})
</script>
<template><PageShell :me="me" :loading="loading" :error="error" active="home"><section class="surface announcement-panel"><div class="section-header"><strong>站点公告</strong></div><div class="announcement-content">{{content || '暂无公告'}}</div></section></PageShell></template>
