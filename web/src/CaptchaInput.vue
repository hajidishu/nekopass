<script setup lang="ts">
import {onMounted,ref} from 'vue'
import {ElMessage} from 'element-plus'
import {api} from './api'
const props=defineProps<{endpoint:string;mode:string}>()
const model=defineModel<{id:string;answer:string}>({required:true})
const image=ref(''),busy=ref(false)
async function refresh(){if(props.mode!=='image')return;busy.value=true;model.value={id:'',answer:''};try{const value=await api<{id:string;image:string}>(props.endpoint);model.value={id:value.id,answer:''};image.value=value.image}catch(e){image.value='';ElMessage.error((e as Error).message)}finally{busy.value=false}}
onMounted(refresh)
defineExpose({refresh})
</script>
<template><el-form-item v-if="mode==='image'" label="图形验证码"><div class="captcha-row"><el-input :model-value="model.answer" @update:model-value="model={...model,answer:$event}" maxlength="6" inputmode="numeric" placeholder="输入图片中的数字"/><button type="button" class="captcha-button" :disabled="busy" @click="refresh" aria-label="刷新图形验证码"><img v-if="image" :src="image" alt="图形验证码" width="160" height="50"/><span v-else>刷新验证码</span></button></div></el-form-item></template>
<style scoped>.captcha-row{display:flex;align-items:center;gap:10px;width:100%}.captcha-button{border:0;background:transparent;padding:0;cursor:pointer;flex-shrink:0}.captcha-button img{display:block;border-radius:10px}@media(max-width:420px){.captcha-row{flex-wrap:wrap}}</style>
