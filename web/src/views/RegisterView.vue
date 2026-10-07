<script setup lang="ts">
import {onMounted,onUnmounted,reactive,ref,watch} from 'vue'
import {ElMessage} from 'element-plus'
import {api} from '../api'
import BrandLogo from '../BrandLogo.vue'
import {site} from '../site'
const config=ref<{enabled:boolean;captcha_mode:string}|null>(null),error=ref(''),busy=ref(false),sending=ref(false),refreshing=ref(false)
const form=reactive({email:'',password:'',confirm_password:'',email_code:'',verification_id:'',invite_code:new URLSearchParams(location.search).get('code')||''})
const captcha=reactive({id:'',image:'',answer:''}),seconds=ref(0)
let timer:ReturnType<typeof setInterval>|undefined
onUnmounted(()=>{if(timer)clearInterval(timer)})
watch(()=>form.email,()=>{form.verification_id='';form.email_code=''})
async function refreshCaptcha(){if(config.value?.captcha_mode!=='image')return;refreshing.value=true;try{const c=await api<{id:string;image:string}>('registration/captcha');Object.assign(captcha,{...c,answer:''})}catch(e){ElMessage.error((e as Error).message)}finally{refreshing.value=false}}
onMounted(async()=>{try{config.value=await api('registration');if(config.value?.enabled)await refreshCaptcha()}catch(e){error.value=(e as Error).message}})
async function sendCode(){
 if(sending.value||seconds.value)return
 sending.value=true
 try{
  const result=await api<{verification_id:string;retry_after:number}>('registration/email-code','POST',{email:form.email,captcha_id:captcha.id,captcha:captcha.answer})
  form.verification_id=result.verification_id;seconds.value=result.retry_after;if(timer)clearInterval(timer)
  timer=setInterval(()=>{if(seconds.value>0)seconds.value--;else if(timer)clearInterval(timer)},1000)
  ElMessage.success('验证码已发送，请查收邮箱')
 }catch(e){ElMessage.error((e as Error).message)}finally{sending.value=false;await refreshCaptcha()}
}
async function register(){
 if(busy.value)return
 if(form.password!==form.confirm_password){ElMessage.error('两次输入的密码不一致');return}
 if(!form.verification_id){ElMessage.error('请先获取邮箱验证码');return}
 busy.value=true
 try{await api('register','POST',form);ElMessage.success('注册成功，请登录');location.assign('/login?email='+encodeURIComponent(form.email))}catch(e){ElMessage.error((e as Error).message)}finally{busy.value=false}
}
</script>
<template><main class="login-page"><section class="login-card surface"><BrandLogo size="large"/><h1>{{site.name}}</h1><p class="subtle">注册账号</p><el-alert v-if="error" :title="error" type="error" :closable="false"/><p v-else-if="config&&!config.enabled">此站点未开放注册，请联系管理员。</p><el-form v-else-if="config?.enabled" label-position="top" @submit.prevent="register"><el-form-item label="电子邮件"><el-input v-model="form.email" type="email" autocomplete="username" maxlength="254"/></el-form-item><el-form-item label="密码"><el-input v-model="form.password" type="password" show-password autocomplete="new-password" placeholder="12–72 字节"/></el-form-item><el-form-item label="确认密码"><el-input v-model="form.confirm_password" type="password" show-password autocomplete="new-password"/></el-form-item><el-form-item v-if="config.captcha_mode==='image'" label="图形验证码"><div class="captcha-row"><el-input v-model="captcha.answer" maxlength="6" inputmode="numeric" placeholder="输入图片中的数字"/><button type="button" class="captcha-button" :disabled="refreshing" @click="refreshCaptcha" aria-label="刷新图形验证码"><img v-if="captcha.image" :src="captcha.image" alt="图形验证码" width="160" height="50"/><span v-else>刷新验证码</span></button></div></el-form-item><el-form-item label="邮箱验证码"><el-input v-model="form.email_code" maxlength="6" inputmode="numeric" autocomplete="one-time-code"><template #append><el-button :loading="sending" :disabled="seconds>0||!form.email" @click="sendCode">{{seconds?seconds+' 秒':'发送验证码'}}</el-button></template></el-input></el-form-item><el-form-item label="邀请码（可选）"><el-input v-model="form.invite_code" maxlength="128"/></el-form-item><el-button type="primary" native-type="submit" :loading="busy" class="full">注册</el-button></el-form><p class="field-tip"><a class="text-link" href="/login">已有账号，返回登录</a></p></section></main></template>
<style scoped>.captcha-row{display:flex;align-items:center;gap:10px;width:100%}.captcha-button{border:0;background:transparent;padding:0;cursor:pointer;flex-shrink:0}.captcha-button img{border-radius:10px;display:block}.login-card{margin:24px 0}@media(max-width:420px){.captcha-row{flex-wrap:wrap}}</style>
