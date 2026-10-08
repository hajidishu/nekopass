<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import Icon from './Icon.vue'
import BrandLogo from './BrandLogo.vue'
import { api, type Me } from './api'
import { applyTheme } from './mount'
import {site} from './site'
defineProps<{ me: Me | null; loading: boolean; error: string; active: string; admin?: boolean }>()
const menuOpen = ref(false), dark = ref(localStorage.getItem('nekopass-theme-v3') !== 'light')
const userLinks = [{path:'/',label:'主页',icon:'home',key:'home'},{path:'/profile',label:'个人中心',icon:'user',key:'profile'},{path:'/forward_rules',label:'转发规则',icon:'rules',key:'rules'},{path:'/shop',label:'商城',icon:'shop',key:'shop'},{path:'/orders',label:'我的订单',icon:'orders',key:'orders'},{path:'/tickets',label:'工单',icon:'rules',key:'tickets'},{path:'/referrals',label:'邀请返利',icon:'user',key:'referrals'},{path:'/node_status',label:'节点状态',icon:'node',key:'probe'}]
const adminLinks = [{path:'/admin/orders',label:'订单查询',icon:'orders',key:'orders'},{path:'/admin',label:'后台首页',icon:'home',key:'admin'},{path:'/admin/tickets',label:'工单管理',icon:'rules',key:'tickets'},{path:'/admin/announcements',label:'公告管理',icon:'edit',key:'announcements'},{path:'/admin/users',label:'用户管理',icon:'user',key:'users'},{path:'/admin/plans',label:'套餐管理',icon:'folder',key:'plans'},{path:'/admin/nodes',label:'节点管理',icon:'node',key:'nodes'},{path:'/admin/payment_gateways',label:'支付方式',icon:'wallet',key:'payment_gateways'},{path:'/admin/settings',label:'系统设置',icon:'settings',key:'settings'}]
async function logout() { try { await api('logout','POST',{}); location.assign('/login') } catch(e) { ElMessage.error((e as Error).message) } }
function retry() { location.reload() }
</script>
<template>
 <div v-if="loading" class="loading">正在加载…</div>
 <main v-else-if="!me" class="page-load-error surface"><h2>暂时无法加载页面</h2><p>{{ error }}</p><a href="/login">返回登录页</a><el-button @click="retry">重试</el-button></main>
 <div v-else class="app-shell"><header class="topbar"><div class="topbar-brand"><button class="mobile-menu icon-button" aria-label="打开菜单" @click="menuOpen=!menuOpen"><Icon name="menu" /></button><a :href="admin ? '/admin' : '/'" :aria-label="site.name"><BrandLogo /><span class="brand-site-name">{{site.name}}</span><span v-if="admin" class="admin-area-badge">管理后台</span></a></div><div class="topbar-actions"><a v-if="admin" class="area-link" href="/">返回用户端</a><a v-else-if="me.is_admin" class="area-link" href="/admin">管理后台</a><el-dropdown trigger="click"><el-button class="account-button"><span class="account-name">{{ me.username }}</span><span class="account-divider"></span><Icon name="user" /></el-button><template #dropdown><el-dropdown-menu><el-dropdown-item><a href="/profile">个人中心</a></el-dropdown-item><el-dropdown-item divided @click="logout">退出登录</el-dropdown-item></el-dropdown-menu></template></el-dropdown><button class="icon-button" :aria-label="dark ? '切换浅色模式' : '切换深色模式'" @click="dark=!dark;applyTheme(dark)"><Icon :name="dark ? 'sun' : 'moon'" /></button></div></header>
 <button v-if="menuOpen" class="menu-backdrop" aria-label="关闭菜单" @click="menuOpen=false"></button><aside class="sidebar" :class="{open:menuOpen}"><nav><a v-for="item in admin ? adminLinks : userLinks" :key="item.path" :href="item.path" :class="{active:active===item.key}" :aria-current="active===item.key ? 'page' : undefined"><Icon :name="item.icon" />{{ item.label }}</a></nav></aside>
 <main class="workspace"><el-alert v-if="error" class="page-load-alert" :title="error" type="error" :closable="false" /><slot /></main></div>
</template>
