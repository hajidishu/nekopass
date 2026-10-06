<script setup lang="ts">
import PageShell from '../PageShell.vue'
import Icon from '../Icon.vue'
import {usePage} from '../page'
const {me,loading,error}=usePage(async()=>{}, {admin:true})
const links=[{path:'/admin/announcements',title:'公告管理',description:'编辑用户主页的站点公告',icon:'edit'},{path:'/admin/users',title:'用户管理',description:'管理账号、套餐分配和用户转发规则',icon:'user'},{path:'/admin/plans',title:'套餐管理',description:'统一配置资源限制和节点组权限',icon:'folder'},{path:'/admin/nodes',title:'节点管理',description:'配置节点运行参数并下发至 Agent',icon:'node'},{path:'/admin/node_groups',title:'节点组管理',description:'管理组内节点、授权范围和显示顺序',icon:'folder'},{path:'/admin/payment_gateways',title:'支付方式',description:'配置支付方式、商户信息和支付接口',icon:'wallet'},{path:'/admin/settings',title:'系统设置',description:'配置面板地址、一键安装与管理 API 密钥',icon:'settings'}]
</script>
<template><PageShell :me="me" :loading="loading" :error="error" active="admin" admin><section class="admin-landing"><h1>管理后台</h1><p class="subtle">选择需要管理的内容</p><div class="admin-entry-grid"><a v-for="item in links" :key="item.path" :href="item.path" class="surface admin-entry-card"><Icon :name="item.icon" /><h2>{{item.title}}</h2><p>{{item.description}}</p><span>进入管理 →</span></a></div></section></PageShell></template>
