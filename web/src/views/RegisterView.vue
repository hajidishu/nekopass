<script setup lang="ts">
import {onMounted,onUnmounted,reactive,ref,watch} from 'vue'
import {ElMessage} from 'element-plus'
import {api} from '../api'
import BrandLogo from '../BrandLogo.vue'
import CaptchaInput from '../CaptchaInput.vue'
import {site} from '../site'
const config=ref<{enabled:boolean;captcha_mode:string;force_invite:boolean;terms_url:string;privacy_url:string}|null>(null),error=ref(''),busy=ref(false),sending=ref(false)
const form=reactive({email:'',password:'',confirm_password:'',email_code:'',verification_id:'',invite_code:new URLSearchParams(location.search).get('code')||''})
const captcha=ref({id:'',answer:''}),captchaInput=ref<{refresh():Promise<void>}>(),seconds=ref(0),termsAccepted=ref(false)
let timer:ReturnType<typeof setInterval>|undefined
onUnmounted(()=>{if(timer)clearInterval(timer)})
watch(()=>form.email,()=>{form.verification_id='';form.email_code=''})
onMounted(async()=>{try{config.value=await api('registration');}catch(e){error.value=(e as Error).message}})
async function sendCode(){
 if(sending.value||seconds.value)return
 sending.value=true
 try{
  const result=await api<{verification_id:string;retry_after:number}>('registration/email-code','POST',{email:form.email,captcha_id:captcha.value.id,captcha:captcha.value.answer,invite_code:form.invite_code})
  form.verification_id=result.verification_id;seconds.value=result.retry_after;if(timer)clearInterval(timer)
  timer=setInterval(()=>{if(seconds.value>0)seconds.value--;else if(timer)clearInterval(timer)},1000)
  ElMessage.success('验证码已发送，请查收邮箱')
 }catch(e){ElMessage.error((e as Error).message)}finally{sending.value=false;await captchaInput.value?.refresh()}
}
async function register(){
 if(busy.value)return
 if((config.value?.terms_url||config.value?.privacy_url)&&!termsAccepted.value){ElMessage.error('请先阅读并同意站点条款');return}
 if(config.value?.force_invite&&!form.invite_code.trim()){ElMessage.error('请填写邀请码');return}
 if(form.password!==form.confirm_password){ElMessage.error('两次输入的密码不一致');return}
 if(!form.verification_id){ElMessage.error('请先获取邮箱验证码');return}
 busy.value=true
 try{await api('register','POST',form);ElMessage.success('注册成功，请登录');location.assign('/login?email='+encodeURIComponent(form.email))}catch(e){ElMessage.error((e as Error).message)}finally{busy.value=false}
}
</script>
<template><main class="login-page"><section class="login-card surface"><BrandLogo size="large"/><h1>{{site.name}}</h1><p class="subtle">注册账号</p><el-alert v-if="error" :title="error" type="error" :closable="false"/><p v-else-if="config&&!config.enabled">此站点未开放注册，请联系管理员。</p><el-form v-else-if="config?.enabled" label-position="top" @submit.prevent="register"><el-form-item label="电子邮件"><el-input v-model="form.email" type="email" autocomplete="username" maxlength="254"/></el-form-item><el-form-item label="密码"><el-input v-model="form.password" type="password" show-password autocomplete="new-password" placeholder="12–72 字节"/></el-form-item><el-form-item label="确认密码"><el-input v-model="form.confirm_password" type="password" show-password autocomplete="new-password"/></el-form-item><CaptchaInput ref="captchaInput" v-model="captcha" endpoint="registration/captcha" :mode="config.captcha_mode"/><el-form-item label="邮箱验证码"><el-input v-model="form.email_code" maxlength="6" inputmode="numeric" autocomplete="one-time-code"><template #append><el-button :loading="sending" :disabled="seconds>0||!form.email" @click="sendCode">{{seconds?seconds+' 秒':'发送验证码'}}</el-button></template></el-input></el-form-item><el-form-item :label="config.force_invite?'邀请码':'邀请码（可选）'" :required="config.force_invite"><el-input v-model="form.invite_code" maxlength="128"/></el-form-item><div v-if="config.terms_url||config.privacy_url" class="registration-terms"><el-checkbox v-model="termsAccepted"><span>我已阅读并同意 <a v-if="config.terms_url" class="text-link" :href="config.terms_url" target="_blank" rel="noopener noreferrer" @click.stop>用户条款</a><span v-if="config.terms_url&&config.privacy_url"> 和 </span><a v-if="config.privacy_url" class="text-link" :href="config.privacy_url" target="_blank" rel="noopener noreferrer" @click.stop>隐私条款</a></span></el-checkbox></div><el-button type="primary" native-type="submit" :loading="busy" class="full">注册</el-button></el-form><p class="field-tip"><a class="text-link" href="/login">已有账号，返回登录</a></p></section></main></template>
<style scoped>.login-card{margin:24px 0}.registration-terms{margin:14px 0 20px}.registration-terms :deep(.el-checkbox){height:auto;align-items:flex-start}.registration-terms :deep(.el-checkbox__label){white-space:normal;line-height:1.7}</style>
