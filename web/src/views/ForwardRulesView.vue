<script setup lang="ts">
import {ref} from 'vue'
import PageShell from '../PageShell.vue'
import RulesPage from '../RulesPage.vue'
import {usePage} from '../page'
import {api,type User,type Rule,type RuleNode} from '../api'
const users=ref<User[]>([]),rules=ref<Rule[]>([]),nodes=ref<RuleNode[]>([])
const {me,loading,error,refresh}=usePage(async()=>{const [u,r,n]=await Promise.all([api<User[]>('profile'),api<Rule[]>('rules'),api<RuleNode[]>('rule-nodes')]);users.value=u;rules.value=r;nodes.value=n},{interval:5000})
</script>
<template><PageShell :me="me" :loading="loading" :error="error" active="rules"><RulesPage v-if="me" :me="me" :users="users" :rules="rules" :nodes="nodes" @refresh="refresh" /></PageShell></template>
