<script setup lang="ts">
import {ref} from 'vue'
import {ElMessage} from 'element-plus'
import PageShell from '../PageShell.vue'
import {usePage} from '../page'
import {api} from '../api'
const draft=ref('')
const {me,loading,error,busy,run}=usePage(async()=>{draft.value=(await api<{content:string}>('admin/announcement')).content},{admin:true})
async function save(){await run(async()=>{await api('admin/announcement','PUT',{content:draft.value});ElMessage.success('公告已发布')})}
</script>
<template><PageShell :me="me" :loading="loading" :error="error" active="announcements" admin><section class="surface"><div class="section-header"><strong>公告管理</strong><a class="text-link" href="/" target="_blank" rel="noopener">查看用户主页 ↗</a></div><div class="section-body announcement-editor"><el-form label-position="top" @submit.prevent="save"><el-form-item label="站点公告"><el-input v-model="draft" type="textarea" :rows="14" placeholder="输入公告内容，支持换行" /></el-form-item><el-button type="primary" native-type="submit" :loading="busy">发布公告</el-button></el-form></div></section></PageShell></template>
