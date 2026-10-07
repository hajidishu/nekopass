<script setup lang="ts">
import {computed,onMounted,onUnmounted,ref} from 'vue'
import {ElMessage} from 'element-plus'
import PageShell from '../PageShell.vue'
import {usePage} from '../page'
import {api} from '../api'
type Notice={id:number;title:string;content:string;truncated:boolean}
const items=ref<Notice[]>([]),page=ref(1),total=ref(0),index=ref(0),switching=ref(false),detail=ref<Notice|null>(null),dialog=ref(false),reading=ref(false)
const current=computed(()=>items.value[index.value]),preview=computed(()=>{const n=current.value;return n?n.content.slice(0,180)+(n.truncated||n.content.length>180?' .....':''):''})
const {me,loading,error,refresh}=usePage(async()=>{const selected=current.value?.id;let data=await api<{items:Notice[];total:number}>('announcements?page='+page.value);if(page.value>1&&(page.value-1)*20>=data.total){page.value=1;data=await api('announcements?page=1')}items.value=data.items;total.value=data.total;const found=items.value.findIndex(n=>n.id===selected);index.value=found>=0?found:Math.min(index.value,Math.max(0,items.value.length-1))},{interval:30000})
let timer:ReturnType<typeof setInterval>|undefined
onMounted(()=>{timer=setInterval(()=>{if(!document.hidden&&!dialog.value)void move(1)},8000)})
onUnmounted(()=>{if(timer)clearInterval(timer)})
async function move(direction:number){if(switching.value||total.value<2)return;const next=index.value+direction;if(next>=0&&next<items.value.length){index.value=next;return}switching.value=true;try{const pages=Math.max(1,Math.ceil(total.value/20));page.value=(page.value-1+direction+pages)%pages+1;await refresh();index.value=direction>0?0:Math.max(0,items.value.length-1)}finally{switching.value=false}}
async function read(){if(!current.value||reading.value)return;reading.value=true;try{detail.value=await api<Notice>('announcements/'+current.value.id);dialog.value=true}catch(e){ElMessage.error((e as Error).message)}finally{reading.value=false}}
</script>
<template><PageShell :me="me" :loading="loading" :error="error" active="home"><section class="surface announcement-panel"><div class="section-header"><strong>站点公告</strong><div v-if="total>1" class="notice-controls"><el-button size="small" :disabled="switching" @click="move(-1)" aria-label="上一条公告">←</el-button><span>{{(page-1)*20+index+1}} / {{total}}</span><el-button size="small" :disabled="switching" @click="move(1)" aria-label="下一条公告">→</el-button></div></div><div v-if="current" class="notice-preview"><Transition name="notice" mode="out-in"><div :key="current.id"><h2>{{current.title}}</h2><p>{{preview}}</p><el-button link type="primary" :loading="reading" @click="read">查看全文</el-button></div></Transition></div><div v-else class="announcement-content">暂无公告</div></section><el-dialog v-model="dialog" :title="detail?.title||'站点公告'" width="760px" class="managed-form-dialog"><p class="notice-full">{{detail?.content}}</p></el-dialog></PageShell></template>
<style scoped>.notice-controls{display:flex;align-items:center;gap:12px;font-size:13px;color:var(--el-text-color-secondary)}.notice-preview{padding:24px;min-height:190px}.notice-preview h2{font-size:19px;margin:0 0 16px}.notice-preview p{white-space:pre-line;line-height:1.9;overflow-wrap:anywhere;max-height:140px;overflow:hidden}.notice-full{white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.9;max-height:65vh;overflow:auto}.notice-enter-active,.notice-leave-active{transition:opacity .18s}.notice-enter-from,.notice-leave-to{opacity:0}</style>
