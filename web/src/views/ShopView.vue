<script setup lang="ts">
import {computed,ref,reactive} from 'vue'
import {ElMessage} from 'element-plus'
import PageShell from '../PageShell.vue'
import {usePage} from '../page'
import {api,quotaText,limitText,type User} from '../api'
import {cycles,yuan,cycleName,dateText,requestKey,type ShopPlan,type Wallet,type Quote} from '../commerce'
const wallet=ref<Wallet|null>(null),plans=ref<ShopPlan[]>([]),profile=ref<User|null>(null)
const selected=reactive<Record<number,string>>({}),rechargeAmount=ref('100.00'),dialog=ref(false),quote=ref<Quote|null>(null),purchaseKey=ref(''),purchaseBusy=ref(false)
const {me,loading,error,busy,run,refresh}=usePage(async()=>{
 const [w,p,u]=await Promise.all([api<Wallet>('wallet'),api<ShopPlan[]>('shop/plans'),api<User[]>('profile')]);wallet.value=w;plans.value=p;profile.value=u[0]||null
 for(const plan of p)if(!(selected[plan.id] in plan.prices))selected[plan.id]=cycles.find(c=>c.key in plan.prices)?.key||''
},{interval:15000})
const insufficient=computed(()=>quote.value!==null&&(wallet.value?.balance_cents||0)<quote.value.amount_cents)
async function preview(plan:ShopPlan){await run(async()=>{quote.value=await api<Quote>('shop/quote','POST',{plan_id:plan.id,cycle:selected[plan.id]});purchaseKey.value=requestKey();dialog.value=true})}
async function purchase(){
 if(!quote.value||purchaseBusy.value)return
 purchaseBusy.value=true
 try{
  await api('shop/purchase','POST',{plan_id:quote.value.plan_id,cycle:quote.value.cycle,expected_price_cents:quote.value.amount_cents,expected_epoch:quote.value.epoch,request_key:purchaseKey.value})
  dialog.value=false;await refresh();ElMessage.success('购买成功，套餐已生效，当前周期已用流量已重置')
 }catch(e){ElMessage.error((e as Error).message)}finally{purchaseBusy.value=false}
}
</script>
<template><PageShell :me="me" :loading="loading" :error="error" active="shop">
 <section class="surface shop-wallet"><div class="section-header"><strong>我的钱包</strong><a class="text-link" href="/orders">我的订单</a></div><div class="section-body">
  <div class="wallet-balance">钱包余额：<strong>{{yuan(wallet?.balance_cents||0)}}</strong><span>元</span></div>
  <section class="shop-recharge"><h3>钱包充值</h3><div class="recharge-amount"><el-input v-model="rechargeAmount" inputmode="decimal" aria-label="充值金额"><template #prepend>充值金额</template><template #append>CNY</template></el-input></div><p>最小充值金额：{{yuan(wallet?.minimum_recharge_cents||1000)}} 元</p><p class="subtle">暂未接入支付通道，可联系管理员充值余额。</p><el-button type="primary" disabled>充值</el-button></section>
  <details v-if="wallet?.entries.length" class="wallet-history"><summary>余额明细</summary><el-table :data="wallet.entries"><el-table-column label="时间" min-width="180"><template #default="{row}">{{dateText(row.created_at)}}</template></el-table-column><el-table-column prop="note" label="说明" min-width="200"/><el-table-column label="金额 / 元" width="130"><template #default="{row}"><span :class="row.amount_cents>=0?'credit-amount':'debit-amount'">{{row.amount_cents>0?'+':''}}{{yuan(row.amount_cents)}}</span></template></el-table-column><el-table-column label="余额 / 元" width="130"><template #default="{row}">{{yuan(row.balance_after_cents)}}</template></el-table-column></el-table><p class="field-tip">显示最近 100 条余额记录。</p></details>
 </div></section>
 <section v-if="profile?.plan_id" class="surface current-subscription"><div class="section-header"><strong>当前套餐 · {{profile.plan_name}}</strong></div><div class="section-body subscription-summary"><span>到期时间：{{dateText(profile.expires_at)}}</span><span>下次流量重置：{{dateText(profile.next_reset_at,'无自动重置')}}</span><p class="field-tip">同套餐续费保留个人资源设置并立即重置已用流量，放弃当前周期剩余时间；后续未开始的月份仍然保留。</p></div></section>
 <section class="surface"><div class="section-header"><strong>购买套餐</strong></div><div class="section-body"><el-empty v-if="!plans.length" description="暂无在售套餐"/><div v-else class="shop-plan-grid"><article v-for="plan in plans" :key="plan.id" class="shop-plan-card"><h3>{{plan.name}}</h3><div class="shop-plan-content"><p v-if="plan.description" class="plan-description">{{plan.description}}</p><dl><dt>付款周期</dt><dd><el-select v-model="selected[plan.id]" :aria-label="plan.name+'付款周期'"><el-option v-for="c in cycles.filter(c=>c.key in plan.prices)" :key="c.key" :value="c.key" :label="c.label"/></el-select></dd><dt>已购 / 购买上限</dt><dd>{{plan.purchase_count}} / {{limitText(plan.purchase_limit)}}</dd><dt>最大规则数</dt><dd>{{limitText(plan.max_rules)}}</dd><dt>{{selected[plan.id]==='onetime'?'总流量':'每月流量'}}</dt><dd>{{quotaText(plan.quota_bytes)}}</dd><dt>每节点限速</dt><dd>{{limitText(plan.speed_mbps,'Mbps')}}</dd></dl><p class="field-tip">{{selected[plan.id]==='onetime'?'永久有效，不自动重置流量；再次购买立即重置。':'按月重置流量，未用额度不累积。'}}</p><el-button type="primary" plain class="full" :loading="busy" :disabled="plan.purchase_limit>0 && plan.purchase_count>=plan.purchase_limit" @click="preview(plan)">{{plan.purchase_limit>0 && plan.purchase_count>=plan.purchase_limit?'已达购买上限':profile?.plan_id===plan.id?'续费':'点击购买'}}（{{yuan(plan.prices[selected[plan.id]]||0)}} 元）</el-button></div></article></div></div></section>
 <el-dialog v-model="dialog" title="确认使用余额购买" width="520px" :close-on-click-modal="!purchaseBusy" :show-close="!purchaseBusy"><template v-if="quote"><el-descriptions :column="1" border><el-descriptions-item label="套餐">{{quote.plan_name}}</el-descriptions-item><el-descriptions-item label="付款周期">{{cycleName(quote.cycle)}}</el-descriptions-item><el-descriptions-item label="扣除余额">{{yuan(quote.amount_cents)}} 元</el-descriptions-item><el-descriptions-item label="钱包余额">{{yuan(wallet?.balance_cents||0)}} 元</el-descriptions-item><el-descriptions-item label="新的到期时间">{{dateText(quote.expires_at)}}</el-descriptions-item><el-descriptions-item label="下次流量重置">{{dateText(quote.next_reset_at,'无自动重置')}}</el-descriptions-item></el-descriptions><p class="field-tip">购买后立即生效并重置当前周期已用流量。{{quote.replaces_plan?'这将替换当前套餐，原套餐剩余时长不折抵余额。':quote.kind==='renewal'?'本次续费保留个人额度和限制，放弃当前周期剩余时间，保留后续月份。':''}}</p><el-alert v-if="insufficient" title="余额不足，请先充值" type="warning" :closable="false"/></template><template #footer><el-button :disabled="purchaseBusy" @click="dialog=false">取消</el-button><el-button type="primary" :disabled="insufficient" :loading="purchaseBusy" @click="purchase">确认扣款</el-button></template></el-dialog>
</PageShell></template>
