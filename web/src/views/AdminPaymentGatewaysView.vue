<script setup lang="ts">
import {reactive,ref} from 'vue'
import {ElMessage,ElMessageBox} from 'element-plus'
import PageShell from '../PageShell.vue'
import {usePage} from '../page'
import {api} from '../api'
type PaymentField={name:string;label:string;placeholder:string;secret:boolean;required:boolean}
type PaymentInterface={id:string;name:string;fields:PaymentField[]}
type PaymentMethod={id:number;name:string;interface:string;config:Record<string,string>;enabled:boolean;sort_order:number}
const methods=ref<PaymentMethod[]>([]),interfaces=ref<PaymentInterface[]>([]),page=ref(1),total=ref(0),dialog=ref(false),editID=ref(0)
const form=reactive({name:'',interface:'epay',config:{} as Record<string,string>,enabled:true,sort_order:0})
const {me,loading,error,busy,run,refresh}=usePage(async()=>{
 const [data,drivers]=await Promise.all([api<{items:PaymentMethod[];total:number}>(`admin/payment-methods?page=${page.value}`),api<PaymentInterface[]>('admin/payment-interfaces')]);methods.value=data.items;total.value=data.total;interfaces.value=drivers
},{admin:true})
function interfaceChanged(){form.config=Object.fromEntries((interfaces.value.find(d=>d.id===form.interface)?.fields||[]).map(f=>[f.name,'']))}
function edit(method?:PaymentMethod){editID.value=method?.id||0;Object.assign(form,{name:method?.name||'',interface:method?.interface||interfaces.value[0]?.id||'epay',config:JSON.parse(JSON.stringify(method?.config||{})),enabled:method?.enabled??true,sort_order:method?.sort_order||0});if(!method)interfaceChanged();dialog.value=true}
async function save(){await run(async()=>{await api(editID.value?`admin/payment-methods/${editID.value}`:'admin/payment-methods',editID.value?'PUT':'POST',form);dialog.value=false;await refresh();ElMessage.success('支付方式已保存')})}
async function remove(method:PaymentMethod){try{await ElMessageBox.confirm('删除后不再提供此支付方式，已创建的订单仍可接收支付通知。','删除支付方式',{type:'warning'});await run(async()=>{await api(`admin/payment-methods/${method.id}`,'DELETE',{});await refresh()})}catch{}}
</script>
<template><PageShell :me="me" :loading="loading" :error="error" active="payment_gateways" admin>
 <section class="surface"><div class="section-header"><strong>支付方式</strong><el-button type="primary" @click="edit()">添加支付方式</el-button></div><div class="section-body">
  <p class="field-tip">支付接口负责对接，支付方式负责展示。可为同一接口创建多个支付方式，分别使用不同商户配置。</p>
  <el-table :data="methods" empty-text="暂无支付方式"><el-table-column prop="name" label="名称" min-width="170"/><el-table-column label="支付接口" min-width="160"><template #default="{row}">{{interfaces.find(d=>d.id===row.interface)?.name||row.interface}}</template></el-table-column><el-table-column label="状态" width="100"><template #default="{row}"><el-tag :type="row.enabled?'success':'info'">{{row.enabled?'启用':'停用'}}</el-tag></template></el-table-column><el-table-column prop="sort_order" label="排序" width="90"/><el-table-column label="操作" width="140"><template #default="{row}"><el-button link type="primary" @click="edit(row)">编辑</el-button><el-button link type="danger" @click="remove(row)">删除</el-button></template></el-table-column></el-table>
  <el-pagination v-model:current-page="page" :page-size="50" :total="total" layout="prev, pager, next, total" class="user-pagination" @current-change="refresh"/>
 </div></section>
 <el-dialog v-model="dialog" :title="editID?'编辑支付方式':'添加支付方式'" width="620px" class="managed-form-dialog"><el-form label-position="top" @submit.prevent="save">
  <el-form-item label="名称"><el-input v-model="form.name" maxlength="80" placeholder="例如：支付宝、微信支付、备用支付宝"/></el-form-item>
  <el-form-item label="支付接口"><el-select v-model="form.interface" @change="interfaceChanged"><el-option v-for="driver in interfaces" :key="driver.id" :value="driver.id" :label="driver.name"/></el-select></el-form-item>
  <el-form-item v-for="field in interfaces.find(d=>d.id===form.interface)?.fields||[]" :key="field.name" :label="field.label" :required="field.required"><el-input v-model="form.config[field.name]" :type="field.secret?'password':'text'" :show-password="field.secret" :placeholder="field.placeholder"/></el-form-item>
  <div class="form-grid"><el-form-item label="排序"><el-input-number v-model="form.sort_order" :min="-1000000" :max="1000000"/></el-form-item><el-form-item label="启用"><el-switch v-model="form.enabled"/></el-form-item></div>
  <p class="field-tip">系统设置中的面板地址须能从公网访问，用于接收付款通知。已创建订单保留创建时的接口配置。</p>
 </el-form><template #footer><el-button @click="dialog=false">取消</el-button><el-button type="primary" :loading="busy" @click="save">保存</el-button></template></el-dialog>
</PageShell></template>
