<script setup lang="ts">
import {ref,computed} from 'vue'
import {ElMessage} from 'element-plus'
import {api} from '../api'
import {usePage} from '../page'
import {copyText} from '../clipboard'
import {yuan} from '../commerce'
import PageShell from '../PageShell.vue'
type Referral={enabled:boolean;eligible?:boolean;message?:string;code?:string;mode?:string;rate?:string;invited_count?:number;earned_cents?:number}
const info=ref<Referral|null>(null)
const {me,loading,error}=usePage(async()=>{info.value=await api('referrals')})
const link=computed(()=>location.origin+'/register?code='+encodeURIComponent(info.value?.code||''))
async function copy(value:string){try{await copyText(value);ElMessage.success('已复制')}catch{ElMessage.error('复制失败，请手动复制')}}
</script>
<template><PageShell :me="me" :loading="loading" :error="error" active="referrals"><section class="surface"><div class="section-header"><strong>邀请返利</strong><a class="text-link" href="/orders">查看返利订单</a></div><div class="section-body"><p v-if="info&&!info.enabled">此站点未开启邀请返利功能</p><template v-else-if="info"><el-alert v-if="!info.eligible" title="管理员已关闭此账号的邀请返利" type="info" :closable="false"/><template v-else><p>受邀用户购买付费套餐后，获得实付金额的 {{info.rate}}% 余额返利。{{info.mode==='first'?'仅首次付费购买返利。':'每次付费购买及续费均返利。'}}</p><el-form label-position="top"><el-form-item label="邀请码"><el-input :model-value="info.code" readonly><template #append><el-button @click="copy(info!.code!)">复制</el-button></template></el-input></el-form-item><el-form-item label="邀请链接"><el-input :model-value="link" readonly><template #append><el-button @click="copy(link)">复制</el-button></template></el-input></el-form-item></el-form></template><div class="form-grid"><p>已邀请：{{info.invited_count||0}} 人</p><p>累计返利：{{yuan(info.earned_cents||0)}} 元</p></div><p class="field-tip">返利直接计入余额，并显示在“我的订单”。充值和免费套餐不参与返利。</p></template></div></section></PageShell></template>
