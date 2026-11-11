<script setup lang="ts">
import {reactive,ref} from 'vue'
import {ElMessage,ElMessageBox} from 'element-plus'
import PageShell from '../PageShell.vue'
import {usePage} from '../page'
import {api} from '../api'
type Config={enabled:boolean;target_ip:string;failure_threshold:number;cooldown_seconds:number;instance_type:string;binding_mode:'instance'|'profile';profile_id:string;auth_token:string;share_group_token:string;account_id:string;region_name:string;instance_id:string;static_ip:boolean}
type Status={state?:string;failures?:number;reachable?:boolean;checked_unix?:number;last_attempt_unix?:number;last_changed_unix?:number;cooldown_until_unix?:number;old_ip?:string;new_ip?:string;error?:string;instance_id?:string;account_id?:string;region_name?:string}
type Details={node_id:number;node_name:string;protocol_version:number;online:boolean;config:Config;generation:number;status:Status;status_received_at:string|null}
const id=location.pathname.match(/^\/admin\/nodes\/([1-9]\d*)\/ip-recovery$/)?.[1]
const data=ref<Details|null>(null),busy=ref(false),initialized=ref(false)
const form=reactive<Config>({enabled:false,target_ip:'',failure_threshold:6,cooldown_seconds:300,instance_type:'ec2',binding_mode:'instance',profile_id:'',auth_token:'',share_group_token:'',account_id:'',region_name:'',instance_id:'',static_ip:false})
const {me,loading,error,refresh}=usePage(async()=>{if(!id)throw Error('节点地址无效');data.value=await api<Details>(`admin/nodes/${id}/ip-recovery`);if(!initialized.value){Object.assign(form,data.value.config);initialized.value=true}},{admin:true,interval:5000})
const states:Record<string,string>={disabled:'已关闭',pending:'等待节点接收配置',checking:'等待检测',healthy:'检测正常',unreachable:'目标不可达',cooldown:'冷却中',changing:'正在请求换 IP',waiting:'等待 IP 变化',uncertain:'结果待确认',error:'操作失败'}
const time=(n?:number)=>n?new Date(n*1000).toLocaleString():'—'
async function save(){busy.value=true;try{await api(`admin/nodes/${id}/ip-recovery`,'PUT',form);await refresh();ElMessage.success('自动换 IP 配置已保存并下发')}catch(e){ElMessage.error((e as Error).message)}finally{busy.value=false}}
async function reset(){try{await ElMessageBox.confirm('请先确认小助理中的换 IP 任务已经结束。重置会解除结果待确认状态，保留冷却时间，重新累计失败次数。','重置检测状态',{confirmButtonText:'重置',cancelButtonText:'取消'});busy.value=true;await api(`admin/nodes/${id}/ip-recovery/reset`,'POST',{});await refresh();ElMessage.success('已通知节点重置等待状态')}catch(e){if(e instanceof Error)ElMessage.error(e.message)}finally{busy.value=false}}
</script>
<template>
 <PageShell :me="me" :loading="loading" :error="error" active="nodes" admin>
  <div class="managed-rules-heading"><a class="back-link" href="/admin/nodes">← 返回节点管理</a><span>{{data?.node_name}} · 自动换 IP</span></div>
  <nav class="admin-resource-tabs"><a href="/admin/nodes">节点管理</a><a :href="`/admin/nodes/${id}/ddns`">DDNS</a><a :href="`/admin/nodes/${id}/ip-recovery`" class="active">自动换 IP</a></nav>
  <section class="surface">
   <div class="section-header"><strong>自动换 IP</strong><el-button type="primary" :loading="busy" @click="save">保存并下发</el-button></div>
   <div class="section-body settings-form">
    <el-alert v-if="data&&data.protocol_version<19" title="此节点需要更新到支持自动换 IP 的版本后才能执行检测。" type="warning" :closable="false"/>
    <el-alert v-else-if="data&&data.protocol_version<36&&form.binding_mode==='profile'" title="此节点需要升级后才能使用档案绑定；升级前不会执行自动换 IP。" type="warning" :closable="false"/>
    <el-form label-position="top" @submit.prevent="save">
     <el-form-item label="启用自动换 IP"><el-switch v-model="form.enabled"/><span class="field-tip">节点每 5 秒 ping 一次目标 IP，连续失败达到设置次数后请求小助理换 IP。关闭后保留配置。</span></el-form-item>
     <el-form-item label="国内检测 IPv4"><el-input v-model="form.target_ip" placeholder="填写可响应 ping 的国内公网 IPv4"/></el-form-item>
     <div class="form-grid"><el-form-item label="连续失败次数"><el-input-number v-model="form.failure_threshold" :min="1" :max="720"/></el-form-item><el-form-item label="换 IP 冷却时间 / 秒"><el-input-number v-model="form.cooldown_seconds" :min="30" :max="86400"/></el-form-item></div>
     <div class="form-section-title">小助理实例</div>
     <el-form-item label="实例类型"><el-select v-model="form.instance_type"><el-option label="EC2" value="ec2"/><el-option label="Lightsail" value="lightsail"/></el-select></el-form-item>
     <el-form-item label="绑定方式"><el-select v-model="form.binding_mode"><el-option label="固定实例 ID" value="instance"/><el-option label="跟随档案 ID" value="profile"/></el-select></el-form-item>
     <el-form-item label="认证 Token"><el-input v-model="form.auth_token" type="password" show-password autocomplete="off" placeholder="小助理的 X-Auth-Token"/></el-form-item>
     <el-form-item label="分享组 Token"><el-input v-model="form.share_group_token" type="password" show-password autocomplete="off" placeholder="使用分享凭证时填写 X-Share-Group-Token"/><span class="field-tip">认证 Token 与分享组 Token 至少填写一个。</span></el-form-item>
     <template v-if="form.binding_mode==='instance'">
      <div class="form-grid"><el-form-item label="小助理账号 ID"><el-input v-model="form.account_id" placeholder="X-Account-Id；仅使用分享凭证时可留空"/></el-form-item><el-form-item label="地区"><el-input v-model="form.region_name" placeholder="例如 ap-southeast-1"/></el-form-item></div>
      <el-form-item :label="form.instance_type==='ec2'?'EC2 实例 ID':'Lightsail 实例名称'"><el-input v-model="form.instance_id" :placeholder="form.instance_type==='ec2'?'i-xxxxxxxxxxxxxxxxx':'实例名称'"/></el-form-item>
     </template>
     <el-form-item v-else label="实例档案 ID"><el-input v-model="form.profile_id" placeholder="填写小助理实例档案的 id"/><span class="field-tip">自动读取档案当前关联的实例、账号和地区，补机后跟随更新。支持分享组 Token。</span></el-form-item>
     <el-form-item label="新 IP 类型"><el-select v-model="form.static_ip"><el-option label="动态 IP" :value="false"/><el-option label="静态 IP" :value="true"/></el-select></el-form-item>
     <p class="field-tip">由节点独立检测并调用 https://api.aws.sb，不启用小助理自带的屏蔽检测。请求处理中不会重复提交；确认 IP 变化后立即检查 DDNS。</p>
    </el-form>
   </div>
  </section>
  <section class="surface"><div class="section-header"><strong>检测状态</strong><el-button :loading="busy" :disabled="!data?.generation||data?.status.state!=='uncertain'" @click="reset">重置等待状态</el-button></div>
   <div class="section-body"><el-descriptions :column="2" border>
    <el-descriptions-item label="节点">{{data?.online?'在线':'离线'}}</el-descriptions-item><el-descriptions-item label="自动换 IP">{{states[data?.status.state||'disabled']}}</el-descriptions-item>
    <el-descriptions-item label="最近 ping">{{data?.status.checked_unix?(data.status.reachable?'可达':'不可达'):'—'}}</el-descriptions-item><el-descriptions-item label="连续失败">{{data?.status.failures||0}} / {{data?.config.failure_threshold||6}}</el-descriptions-item>
    <el-descriptions-item label="最近检测">{{time(data?.status.checked_unix)}}</el-descriptions-item><el-descriptions-item label="最近请求">{{time(data?.status.last_attempt_unix)}}</el-descriptions-item>
    <el-descriptions-item label="最近 IP 变化">{{time(data?.status.last_changed_unix)}}</el-descriptions-item><el-descriptions-item label="冷却结束">{{time(data?.status.cooldown_until_unix)}}</el-descriptions-item>
    <el-descriptions-item label="原 IP">{{data?.status.old_ip||'—'}}</el-descriptions-item><el-descriptions-item label="新 IP">{{data?.status.new_ip||'—'}}</el-descriptions-item>
    <el-descriptions-item label="当前实例">{{data?.status.instance_id||'—'}}</el-descriptions-item><el-descriptions-item label="当前地区">{{data?.status.region_name||'—'}}</el-descriptions-item>
    <el-descriptions-item v-if="data?.status.error" label="反馈" :span="2">{{data.status.error}}</el-descriptions-item>
   </el-descriptions></div>
  </section>
 </PageShell>
</template>
