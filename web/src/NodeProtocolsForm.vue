<script setup lang="ts">
import type {NodeProtocolsInput} from './node-protocol'
import {toRefs} from 'vue'
const props=defineProps<{form:NodeProtocolsInput;nodes:{id:number;name:string;ingress_enabled:boolean}[];nodeID:number}>()
const {form:nodeForm,nodes,nodeID:editID}=toRefs(props)
const dnsJSON=defineModel<string>('dnsJSON',{required:true})
defineEmits<{submit:[]}>()
function exitChanged(enabled:boolean|string|number){if(!enabled)nodeForm.value.allowed_ingress_ids=[]}
</script>
<template>
<el-form label-position="top" @submit.prevent="$emit('submit')">
    <div class="form-section-title">入口配置</div>
    <p class="field-tip">入口按用户所选出口的协议连接；TLS 客户端配置与本节点的出口协议独立。</p>
    <el-form-item label="允许作为入口">
    <el-switch v-model="nodeForm.ingress_enabled" />
    <span class="field-tip switch-hint">关闭后用户不能将此节点选作入口；开启下方出口功能即可作为专用出口。</span>
    </el-form-item>
    <el-form-item v-if="nodeForm.ingress_enabled" label="允许用户选择直转">
    <el-switch v-model="nodeForm.allow_direct" />
    <span class="field-tip switch-hint">关闭后，此入口的规则必须选择已关联的出口节点。</span>
    </el-form-item>
    <template v-if="nodeForm.ingress_enabled">
    <div class="form-section-title">TLS 客户端</div>
    <div class="form-grid">
    <el-form-item label="uTLS 指纹">
    <el-select v-model="nodeForm.tls.fingerprint">
    <el-option label="关闭（标准 TLS）" value="off"/>
    <el-option label="Chrome（库内预设）" value="chrome"/>
    <el-option label="Firefox（库内预设）" value="firefox"/>
    </el-select>
    </el-form-item>
    <el-form-item label="可选 SNI 覆盖">
    <el-input v-model="nodeForm.tls.client_sni" placeholder="留空使用出口证书域名"/>
    </el-form-item>
    <el-form-item label="每出口 TLS 连接池上限">
    <el-input-number v-model="nodeForm.tls.pool_size" :min="1" :max="8"/>
    </el-form-item>
    </div>
    </template>
    <div class="form-section-title">出口配置</div>
    <el-form-item label="作为出口节点">
<el-switch v-model="nodeForm.tunnel_exit_enabled" @change="exitChanged" />
    </el-form-item>
    <el-form-item label="出口传输协议">
    <el-select v-model="nodeForm.tunnel_protocol">
    <el-option label="明文 TCP" value="plain_tcp" />
    <el-option label="tls+h2" value="tls_h2" />
    </el-select>
    <span class="field-tip">节点作为出口时使用此协议；作为入口时按规则所选出口的协议连接。</span>
    </el-form-item>
    <template v-if="nodeForm.tunnel_exit_enabled">
    <div class="form-grid">
    <el-form-item label="隧道对外地址">
    <el-input v-model="nodeForm.tunnel_public_host" placeholder="入口节点可访问的域名或 IP" />
    </el-form-item>
    <el-form-item label="出口监听地址">
    <el-input v-model="nodeForm.tunnel_listen_host" placeholder="0.0.0.0" />
    </el-form-item>
    <el-form-item label="出口监听端口">
    <el-input-number v-model="nodeForm.tunnel_listen_port" :min="1" :max="65535" />
    </el-form-item>
    </div>
    <template v-if="nodeForm.tunnel_protocol==='tls_h2'">
    <div class="form-section-title">tls+h2 出口</div>
    <p class="field-tip">新增回退行为需出口 v0.14.1 或更新版本。Host、路径或认证不匹配时执行下方 Fallback 配置。</p>
    <div class="form-grid">
    <el-form-item label="证书域名 / SNI">
    <el-input v-model="nodeForm.tls.server_name" placeholder="你拥有的域名" />
    </el-form-item>
    <el-form-item label="公网隧道端口">
    <el-input-number v-model="nodeForm.tls.public_port" :min="0" :max="65535" />
    <span class="field-tip">0 使用监听端口；支持 NAT / TCP 透传。</span>
    </el-form-item>
    <el-form-item label="证书模式">
    <el-select v-model="nodeForm.tls.certificate_mode">
    <el-option label="自签名（自动生成并下发信任）" value="self_signed"/>
    <el-option label="手动导入证书" value="import"/>
    <el-option label="DNS 自动申请 / 续期" value="acme_dns"/>
    <el-option label="HTTP 自动申请 / 续期" value="acme_http"/>
    </el-select>
    </el-form-item>
    <el-form-item label="HTTP Path">
    <el-input v-model="nodeForm.tls.path"/>
    </el-form-item>
    <el-form-item label="HTTP Host">
    <el-input v-model="nodeForm.tls.host" placeholder="留空使用证书域名，可带端口" />
    </el-form-item>
    </div>
    <div class="form-section-title">未认证访问 / Fallback</div>
    <el-form-item label="Fallback 网站地址">
    <el-input v-model="nodeForm.tls.fallback_url" placeholder="https://www.example.com（留空返回普通 404）" />
    <span class="field-tip">用于出口节点：未通过认证的请求反向代理到此网站。网站不可用或留空时返回普通 404；HTTPS 网站还可接管部分握手早期失败的连接。</span>
    </el-form-item>
    <template v-if="nodeForm.tls.certificate_mode==='import'">
    <el-form-item label="证书链 PEM">
    <el-input v-model="nodeForm.tls.certificate" type="textarea" :rows="4"/>
    </el-form-item>
    <el-form-item label="匹配的私钥 PEM">
    <el-input v-model="nodeForm.tls.private_key" type="textarea" :rows="4"/>
    </el-form-item>
    <el-form-item label="可选私有 CA">
    <el-input v-model="nodeForm.tls.root_ca" type="textarea" :rows="3"/>
    </el-form-item>
    </template>
    <template v-if="nodeForm.tls.certificate_mode.startsWith('acme_')">
    <p class="field-tip">保存自动申请配置即授权向所选 CA 申请证书并接受其服务条款。DNS 密钥只由主控使用，不下发节点。</p>
    <div class="form-grid">
    <el-form-item label="ACME 邮箱">
    <el-input v-model="nodeForm.tls.acme_email"/>
    </el-form-item>
    <el-form-item label="ACME Directory HTTPS 地址">
    <el-input v-model="nodeForm.tls.acme_directory"/>
    </el-form-item>
    <el-form-item v-if="nodeForm.tls.certificate_mode==='acme_http'" label="节点 HTTP 验证监听端口">
    <el-input-number v-model="nodeForm.tls.http_challenge_port" :min="1" :max="65535"/>
    <span class="field-tip">CA 从公网 80 验证；使用其他本地端口需配置转发。</span>
    </el-form-item>
    <el-form-item v-else label="DNS 服务商">
    <el-select v-model="nodeForm.tls.dns_provider">
    <el-option label="Cloudflare" value="cloudflare"/>
    <el-option label="阿里 DNS" value="alidns"/>
    <el-option label="DNSPod" value="dnspod"/>
    </el-select>
    </el-form-item>
    </div>
    <el-form-item label="可选 ACME 私有根 CA">
    <el-input v-model="nodeForm.tls.acme_root_ca" type="textarea" :rows="2" placeholder="公共 CA 留空；私有测试 CA 填公开证书"/>
    </el-form-item>
    <el-form-item label="可选签发根 CA">
    <el-input v-model="nodeForm.tls.root_ca" type="textarea" :rows="2" placeholder="公共 CA 留空；用于入口验证私有 CA 签发的证书"/>
    </el-form-item>
    <el-form-item v-if="nodeForm.tls.certificate_mode==='acme_dns'" label="DNS 凭据 JSON">
    <el-input v-model="dnsJSON" type="textarea" :rows="4"/>
    <span class="field-tip">Cloudflare：api_token、可选 zone_token；阿里 DNS：access_key_id、access_key_secret；DNSPod：login_token。</span>
    </el-form-item>
    </template>
    </template>
    <el-form-item label="允许哪些入口使用此出口">
    <el-select v-model="nodeForm.allowed_ingress_ids" multiple filterable placeholder="选择入口节点">
    <el-option v-for="n in nodes.filter(n=>n.id!==editID && n.ingress_enabled)" :key="n.id" :label="n.name" :value="n.id" />
    </el-select>
    <span class="field-tip">用户还需要同时获得入口和出口所属节点组的套餐权限。</span>
    </el-form-item>
    </template>
    <template v-if="nodeForm.ingress_enabled || (nodeForm.tunnel_exit_enabled && nodeForm.tunnel_protocol==='tls_h2')">
    <div class="form-section-title">HTTP2 流控</div>
    <p class="field-tip">每流窗口用于入口下载，连接总窗口在入口和出口均生效。出口 SETTINGS 使用普通 HTTP/2 默认值；业务流上限在认证后生效，并受协议并发上限约束。</p>
    <div class="form-grid">
    <el-form-item label="每流接收窗口 / MiB">
    <el-input-number v-model="nodeForm.tls.stream_window_mib" :min="1" :max="64"/>
    </el-form-item>
    <el-form-item label="每连接接收窗口 / MiB">
    <el-input-number v-model="nodeForm.tls.connection_window_mib" :min="nodeForm.tls.stream_window_mib" :max="256"/>
    </el-form-item>
    <el-form-item label="每 TLS 连接并发流">
    <el-input-number v-model="nodeForm.tls.max_streams" :min="1" :max="1024"/>
    </el-form-item>
    </div>
    </template>
    </el-form>
</template>
