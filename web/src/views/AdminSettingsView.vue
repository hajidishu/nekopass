<script setup lang="ts">
import { copyText } from '../clipboard'
import { computed,onUnmounted,reactive,ref } from 'vue'
import { ElMessage,ElMessageBox } from 'element-plus'
import PageShell from '../PageShell.vue'
import {usePage} from '../page'
import {api} from '../api'
import {loadSite} from '../site'
type Settings={site_name:string;panel_url:string;agent_host:string;agent_port:number;agent_transport:string;installer_url:string;release_base_url:string;agent_version:string;install_token_minutes:number}
const form=reactive<Settings>({site_name:'Nekopass',panel_url:'',agent_host:'',agent_port:9443,agent_transport:'tls',installer_url:'https://github.com/hajidishu/nekopass/releases/latest/download/install-agent.sh',release_base_url:'https://github.com/hajidishu/nekopass/releases/download',agent_version:'latest',install_token_minutes:30})
const updateInfo=ref<{current_version:string;latest:{version:string;url:string};update_available:boolean}|null>(null),checkingUpdate=ref(false)
async function checkUpdate(){checkingUpdate.value=true;try{updateInfo.value=await api('admin/updates')}catch(e){ElMessage.error((e as Error).message)}finally{checkingUpdate.value=false}}
type PanelUpdateStatus={supported:boolean;current_version:string;task:{version:string;state:string;error?:string}|null}
const panelStatus=ref<PanelUpdateStatus|null>(null),submittingUpdate=ref(false)
const updating=computed(()=>panelStatus.value?.task?.state==='queued'||panelStatus.value?.task?.state==='running')
const updateText:Record<string,string>={queued:'等待更新',running:'正在更新，面板可能短暂重启',completed:'更新完成',failed:'更新失败'}
let updateTimer:ReturnType<typeof setTimeout>|undefined,stopped=false
onUnmounted(()=>{stopped=true;if(updateTimer)clearTimeout(updateTimer)})
async function pollPanelUpdate(){
 if(stopped)return
 try{
  panelStatus.value=await api<PanelUpdateStatus>('admin/updates/panel')
  if(panelStatus.value.task?.state==='completed'&&updatingBeforePoll){ElMessage.success('面板更新完成');updateTimer=setTimeout(()=>{if(!stopped)location.reload()},1200);return}
 }catch{/* Retry while the service restarts. */}
 if(!stopped&&updating.value)updateTimer=setTimeout(()=>{updatingBeforePoll=true;void pollPanelUpdate()},2000)
}
let updatingBeforePoll=false
async function updatePanel(){
 submittingUpdate.value=true
 try{
  const info=await api<NonNullable<typeof updateInfo.value>>('admin/updates');updateInfo.value=info
  if(!info.update_available){ElMessage.info('已是最新版本');return}
  const task=await api<NonNullable<PanelUpdateStatus['task']>>('admin/updates/panel','POST',{version:info.latest.version})
  panelStatus.value={supported:true,current_version:info.current_version,task};updatingBeforePoll=true
  ElMessage.success('更新任务已提交');void pollPanelUpdate()
 }catch(e){ElMessage.error((e as Error).message)}finally{submittingUpdate.value=false}
}
const hasKey=ref(false),customKey=ref(''),shownKey=ref(''),keyDialog=ref(false)
const {me,loading,error,busy,run}=usePage(async()=>{const data=await api<{settings:Settings;api_key_configured:boolean}>('admin/settings');Object.assign(form,data.settings);hasKey.value=data.api_key_configured;await pollPanelUpdate()},{admin:true})
function currentAddress(){form.panel_url=location.origin;form.agent_host=location.hostname.replace(/^\[|\]$/g,'')}
async function save(){await run(async()=>{await api('admin/settings','PUT',form);await loadSite();ElMessage.success('系统设置已保存')})}
async function key(){try{if(hasKey.value)await ElMessageBox.confirm('生成或设置新密钥会使旧管理 API 密钥失效。','更新管理密钥',{confirmButtonText:'更新',cancelButtonText:'取消'});await run(async()=>{const data=await api<{key:string}>('admin/settings/api-key','POST',{key:customKey.value});shownKey.value=data.key;customKey.value='';hasKey.value=true;keyDialog.value=true})}catch{/* cancelled */}}
async function revoke(){try{await ElMessageBox.confirm('撤销后，现有管理 API 密钥将不能调用后台接口。','撤销管理密钥',{confirmButtonText:'撤销',cancelButtonText:'取消'});await run(async()=>{await api('admin/settings/api-key','DELETE',{});hasKey.value=false;ElMessage.success('管理 API 密钥已撤销')})}catch{/* cancelled */}}
async function copyKey(){try{await copyText(shownKey.value);ElMessage.success('密钥已复制')}catch{ElMessage.warning('复制失败，请手动选择复制')}}
</script>
<template><PageShell :me="me" :loading="loading" :error="error" active="settings" admin><section class="surface"><div class="section-header"><strong>系统设置</strong><el-button type="primary" :loading="busy" @click="save">保存设置</el-button></div><div class="section-body settings-form"><el-form label-position="top" @submit.prevent="save"><div class="form-section-title">软件更新</div><el-button :loading="checkingUpdate" @click="checkUpdate">检查更新</el-button><el-button type="primary" :loading="submittingUpdate||updating" :disabled="!panelStatus?.supported||updating" @click="updatePanel">立即更新</el-button><p v-if="panelStatus?.task" class="field-tip">{{updateText[panelStatus.task.state]||panelStatus.task.state}} · {{panelStatus.task.version}} {{panelStatus.task.error||''}}</p><p v-if="panelStatus&&!panelStatus.supported" class="field-tip">此旧安装尚未配置更新服务，首次启用请在服务器执行 <code>sudo /opt/nekopass/bin/nekopass-update --service nekopass --setup-panel</code>。</p><p v-if="updateInfo" class="field-tip">当前主控 {{updateInfo.current_version}} · 最新版本 <a :href="updateInfo.latest.url" target="_blank" rel="noopener">{{updateInfo.latest.version}}</a> · {{updateInfo.update_available?'有可用更新':'已是最新版本'}}。点击「立即更新」升级面板，更新时会短暂重启；节点更新在节点管理操作。</p><div class="form-section-title">站点与连接地址</div><el-form-item label="站点名称"><el-input v-model="form.site_name" maxlength="64" /></el-form-item><el-form-item label="面板对外地址"><el-input v-model="form.panel_url" placeholder="https://panel.example.com" /><el-button class="settings-inline-action" @click="currentAddress">填入当前面板地址</el-button></el-form-item><div class="form-grid"><el-form-item label="Agent 主控域名 / IP"><el-input v-model="form.agent_host" placeholder="panel.example.com" /></el-form-item><el-form-item label="Agent 控制端口"><el-input-number v-model="form.agent_port" :min="1" :max="65535" /></el-form-item></div><el-form-item label="节点连接方式"><el-select v-model="form.agent_transport"><el-option label="TLS（公共 CA 可信证书）" value="tls"/><el-option label="明文 HTTP/2（测试环境）" value="plain"/></el-select><span class="field-tip">只决定节点安装命令的 http/https 地址；主控实际监听方式由安装器或反向代理配置。</span></el-form-item><p class="field-tip">填写节点能访问的外部地址。面板访问端口与 Agent 控制端口可以不同；此处不会修改主控服务的实际监听端口，也不会自动改变已有节点的连接地址。</p><div class="form-section-title">节点一键安装</div><p class="field-tip">一键安装始终可用。默认从 GitHub Releases 下载，也可修改为自己的 HTTPS 下载源。</p><el-form-item label="安装脚本地址"><el-input v-model="form.installer_url" placeholder="https://github.com/hajidishu/nekopass/releases/latest/download/install-agent.sh" /></el-form-item><el-form-item label="Agent 版本下载根地址"><el-input v-model="form.release_base_url" placeholder="https://github.com/hajidishu/nekopass/releases/download" /></el-form-item><div class="form-grid"><el-form-item label="Agent 版本"><el-input v-model="form.agent_version" placeholder="latest" /></el-form-item></div><el-button type="primary" :loading="busy" native-type="submit">保存设置</el-button></el-form><div class="form-section-title api-key-section">管理 API 密钥</div><p class="subtle">{{hasKey?'已配置管理 API 密钥。原值不会再次显示。':'尚未配置管理 API 密钥。'}}此密钥用于自动化管理接口，不是节点密钥，也不会包含在节点安装命令中。</p><el-input v-model="customKey" type="password" show-password autocomplete="new-password" placeholder="可填写 32–256 字符自定义密钥，留空自动生成" /><div class="admin-actions settings-key-actions"><el-button :loading="busy" @click="key">{{hasKey?'更新管理 API 密钥':'生成管理 API 密钥'}}</el-button><el-button v-if="hasKey" type="danger" plain :loading="busy" @click="revoke">撤销密钥</el-button></div></div></section><el-dialog v-model="keyDialog" title="保存管理 API 密钥" width="600px" @closed="shownKey=''" ><p>只显示这一次，请保存到自己的密钥管理工具中。</p><el-input :model-value="shownKey" type="textarea" :rows="3" readonly /><template #footer><el-button type="primary" @click="copyKey">复制密钥</el-button></template></el-dialog></PageShell></template>
