<script setup lang="ts">
import {ref} from 'vue'
import PageShell from '../PageShell.vue'
import {usePage} from '../page'
import {yuan,dateText} from '../commerce'
import {api,bytes,quotaText,limitText,type User} from '../api'
const profile=ref<User|null>(null)
const {me,loading,error}=usePage(async()=>{profile.value=(await api<User[]>('profile'))[0]||null},{interval:5000})
</script>
<template><PageShell :me="me" :loading="loading" :error="error" active="profile"><section v-if="me" class="surface"><div class="section-header"><strong>个人中心</strong></div><div class="section-body"><el-descriptions :column="1" border><el-descriptions-item label="用户名">{{me.username}}</el-descriptions-item><el-descriptions-item label="角色">{{me.is_admin ? '管理员' : '用户'}}</el-descriptions-item><el-descriptions-item label="钱包余额">{{yuan(profile?.balance_cents||0)}} 元 <a class="text-link" href="/shop">前往商城</a></el-descriptions-item><el-descriptions-item label="下次流量重置">{{dateText(profile?.next_reset_at,'无自动重置')}}</el-descriptions-item><el-descriptions-item label="当前套餐">{{profile?.plan_name || '未分配'}}</el-descriptions-item><el-descriptions-item label="到期时间">{{!profile?.plan_id ? '未分配套餐' : profile.expires_at ? new Date(profile.expires_at).toLocaleString() : '永不到期'}}</el-descriptions-item><el-descriptions-item label="每节点双向限速">{{profile?.plan_id ? limitText(profile.speed_mbps,'Mbps') : '—'}}</el-descriptions-item><el-descriptions-item label="流量 / 总额度">{{bytes(profile?.traffic_bytes || 0)}} / {{profile?.plan_id ? quotaText(profile.quota_bytes) : '未分配套餐'}}</el-descriptions-item><el-descriptions-item label="规则上限">{{profile?.plan_id ? limitText(profile.max_rules) : '—'}}</el-descriptions-item></el-descriptions></div></section></PageShell></template>
