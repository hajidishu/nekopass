<script setup lang="ts">
import {ref} from 'vue'
import PageShell from '../PageShell.vue'
import RulesPage from '../RulesPage.vue'
import {usePage} from '../page'
import {api,type User,type Rule,type RuleNode} from '../api'
const userID=location.pathname.match(/^\/admin\/users\/([1-9]\d*)\/forward_rules$/)?.[1]
const user=ref<User|null>(null),rules=ref<Rule[]>([]),nodes=ref<RuleNode[]>([])
const {me,loading,error,refresh}=usePage(async()=>{if(!userID)throw new Error('用户地址无效');const prefix=`admin/users/${userID}`;const[u,r,n]=await Promise.all([api<User[]>(prefix),api<Rule[]>(prefix+'/rules'),api<RuleNode[]>(prefix+'/rule-nodes')]);user.value=u[0]||null;rules.value=r;nodes.value=n},{admin:true,interval:5000})
</script>
<template><PageShell :me="me" :loading="loading" :error="error" active="users" admin><template v-if="me && user"><div class="managed-rules-heading"><a class="back-link" href="/admin/users">← 返回用户管理</a><span>{{user.username}} · {{user.plan_name}}</span></div><RulesPage :me="me" :users="[user]" :nodes="nodes" :rules="rules" :managed-user="user" @refresh="refresh" /></template></PageShell></template>
