<script setup lang="ts">
import PageShell from '../PageShell.vue'
import {usePage} from '../page'
const {me,loading,error}=usePage(async()=>{}, {admin:true})
</script>
<template><PageShell :me="me" :loading="loading" :error="error" active="payment_gateways" admin><section class="surface"><div class="section-header"><strong>付款网关</strong></div><div class="section-body"><el-empty description="暂未接入付款网关"/><p class="gateway-placeholder">此处预留支付通道配置入口，后续用于配置商户信息与充值回调。当前可在用户管理中为用户充值余额，套餐统一使用余额购买。</p><a class="text-link" href="/admin/users">前往用户管理充值余额 →</a></div></section></PageShell></template>
