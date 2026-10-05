<script setup lang="ts">
import { reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api, type Me } from '../api'
import { safeReturnPath } from '../page'
import {site} from '../site'
import BrandLogo from '../BrandLogo.vue'
const form = reactive({username:'',password:''}), busy = ref(false)
async function login() {
 if (busy.value) return
 busy.value=true
 try {
  await api<Me>('login','POST',form)
  form.password=''
  let me: Me
  try { me=await api<Me>('me') } catch { throw new Error('登录状态未能保存，请确认浏览器允许本站 Cookie 后重试。') }
  location.assign(safeReturnPath(new URLSearchParams(location.search).get('next'),me.is_admin))
 } catch(e) { ElMessage.error((e as Error).message) } finally { busy.value=false }
}
</script>
<template><main class="login-page"><section class="login-card surface"><BrandLogo size="large" /><h1>{{site.name}}</h1><p class="subtle">登录控制台</p><el-form label-position="top" @submit.prevent="login"><el-form-item label="用户名"><el-input v-model="form.username" autocomplete="username" /></el-form-item><el-form-item label="密码"><el-input v-model="form.password" type="password" show-password autocomplete="current-password" /></el-form-item><el-button type="primary" native-type="submit" :loading="busy" class="full">登录</el-button></el-form></section></main></template>
