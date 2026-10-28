import type {NodeInput,TunnelTLS} from './api'
export const nodeTLSDefaults = ():TunnelTLS => ({quic_padding:{enabled:false,max_padding:1400,burst_bytes:8192,bytes_per_second:8192},padding_enabled:false,padding_scheme:[],server_name:'',client_sni:'',fingerprint:'off',certificate_mode:'self_signed',certificate:'',private_key:'',root_ca:'',host:'',fallback_url:'',path:'/api/stream',public_port:0,pool_size:2,stream_window_mib:16,connection_window_mib:64,max_streams:256,site_title:'Welcome',acme_email:'',acme_directory:'https://acme-v02.api.letsencrypt.org/directory',acme_root_ca:'',http_challenge_port:80,dns_provider:'cloudflare',dns_credentials:{} as Record<string,string>})
export function nodeTLSConfig(input?:Partial<TunnelTLS>|null):TunnelTLS{const defaults=nodeTLSDefaults();return {...defaults,...input,quic_padding:{...defaults.quic_padding,...input?.quic_padding}}}
export type NodeProtocolsInput = Pick<NodeInput,'ingress_multiplier'|'egress_multiplier'|'random'|'tls'|'ingress_enabled'|'allow_direct'|'tunnel_exit_enabled'|'tunnel_protocol'|'tunnel_transport'|'tunnel_security'|'tunnel_listen_host'|'tunnel_listen_port'|'tunnel_public_host'|'allowed_ingress_ids'>
export const protocolDefaults = ():NodeProtocolsInput => ({ingress_multiplier:'1',egress_multiplier:'0',random:{cipher:'chacha20-poly1305',key:''},tls:nodeTLSDefaults(),ingress_enabled:true,allow_direct:true,tunnel_exit_enabled:false,tunnel_protocol:'plain_tcp',tunnel_transport:'raw_tcp',tunnel_security:'none',tunnel_listen_host:'0.0.0.0',tunnel_listen_port:0,tunnel_public_host:'',allowed_ingress_ids:[]})
const transportFields=['host','path','pool_size','stream_window_mib','connection_window_mib','max_streams'] as const
export type NodeTransportInput={tunnel_transport:string;tls:Pick<TunnelTLS,typeof transportFields[number]>}
export function nodeTransportInput(form:NodeProtocolsInput):NodeTransportInput{
 return {tunnel_transport:form.tunnel_transport,tls:Object.fromEntries(transportFields.map(key=>[key,form.tls[key]])) as NodeTransportInput['tls']}
}
export function applyNodeTransport(form:NodeProtocolsInput,input:NodeTransportInput){form.tunnel_transport=input.tunnel_transport;Object.assign(form.tls,input.tls);if(form.tunnel_transport==='h3'){form.tunnel_security='tls';form.tls.fingerprint='off'}}
const securityFields=['quic_padding','padding_enabled','padding_scheme','server_name','client_sni','fingerprint','certificate_mode','certificate','private_key','root_ca','fallback_url','site_title','acme_email','acme_directory','acme_root_ca','http_challenge_port','dns_provider','dns_credentials'] as const
export type NodeSecurityInput={tunnel_security:string;random:{cipher:string;key:string};tls:Pick<TunnelTLS,typeof securityFields[number]>}
export function nodeSecurityInput(form:NodeProtocolsInput):NodeSecurityInput{
 return JSON.parse(JSON.stringify({tunnel_security:form.tunnel_security,random:form.random||{cipher:'chacha20-poly1305',key:''},tls:Object.fromEntries(securityFields.map(key=>[key,form.tls[key]]))}))
}
export function applyNodeSecurity(form:NodeProtocolsInput,input:NodeSecurityInput){form.tunnel_security=form.tunnel_transport==='h3'?'tls':input.tunnel_security;form.random={...input.random};Object.assign(form.tls,input.tls)}
export function nodeDNSCredentials(form:NodeProtocolsInput,text:string){
 if(form.tunnel_security!=='tls'||form.tls.certificate_mode!=='acme_dns')return form.tls.dns_credentials
 const value:unknown=JSON.parse(text)
 if(!value||typeof value!=='object'||Array.isArray(value))throw new Error('DNS 凭据须为 JSON 对象')
 return value as Record<string,string>
}
