// Build web first. Only fixture APIs are used; no live administrator credentials.
const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const http=require('node:http');const fs=require('node:fs');const path=require('node:path');
const root=path.resolve(__dirname,'../web/dist');
const server=http.createServer((req,res)=>{
 let name=new URL(req.url,'http://localhost').pathname;if(name==='/admin/nodes')name='/pages/admin_nodes.html';
 const file=path.resolve(root,'.'+name);if(!file.startsWith(root+path.sep)||!fs.existsSync(file)){res.writeHead(404);res.end();return}
 res.setHeader('Content-Type',({'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css','.svg':'image/svg+xml'})[path.extname(file)]||'application/octet-stream');fs.createReadStream(file).pipe(res);
});
(async()=>{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const browser=await chromium.launch({headless:true,...(process.env.NEKOPASS_BROWSER?{executablePath:process.env.NEKOPASS_BROWSER}:{})});
 try{
  const original={id:6,name:'配置测试节点',token:'fixture-key',public_address:'exit.example.test',notes:'',enabled:true,group_ids:[],listen_host:'0.0.0.0',port_min:1024,port_max:65535,max_connections:10000,dial_timeout_seconds:8,idle_timeout_seconds:300,udp_idle_timeout_seconds:60,probe_interval_seconds:5,disk_path:'/',network_interfaces:[],ingress_enabled:true,allow_direct:true,tunnel_exit_enabled:false,tunnel_protocol:'plain_tcp',tunnel_transport:'raw_tcp',tunnel_security:'none',tunnel_listen_host:'0.0.0.0',tunnel_listen_port:27443,tunnel_public_host:'exit.example.test',allowed_ingress_ids:[],tls:{server_name:'exit.example.test',fingerprint:'off',certificate_mode:'self_signed',padding_enabled:false,padding_scheme:[]},online:true,sync_error:'',applied_revision:1,config_revision:1,active_connections:0};
  let saved=structuredClone(original);const writes=[],errors=[];
  const page=await browser.newPage({viewport:{width:1440,height:1050}});page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/api/v1/**',async route=>{
   const request=route.request(),url=new URL(request.url()),endpoint=url.pathname;
   if(request.method()!=='GET'){writes.push({endpoint,body:request.postDataJSON()});if(endpoint==='/api/v1/admin/nodes/6')saved={...saved,...request.postDataJSON()};return route.fulfill({json:{id:endpoint.endsWith('/6')?6:8,token:'fixture-key'}})}
   if(endpoint.endsWith('/me'))return route.fulfill({json:{id:1,username:'fixture',is_admin:true}});
   if(endpoint==='/api/v1/admin/nodes')return route.fulfill({json:[saved]});
   if(endpoint==='/api/v1/admin/node-groups')return route.fulfill({json:[]});
   return route.fulfill({json:{site_name:'Nekopass'}});
  });
  await page.goto('http://127.0.0.1:'+server.address().port+'/admin/nodes');
  await page.getByRole('row').filter({hasText:'配置测试节点'}).getByRole('button',{name:'编辑',exact:true}).click();
  let parent=page.getByRole('dialog',{name:'编辑节点',exact:true});
  const field=(container,label)=>container.getByText(label,{exact:true}).locator('..');
  const input=(container,label)=>field(container,label).locator('input').first();
  async function select(container,label,value){await field(container,label).locator('.el-select').click();await page.getByRole('option',{name:value,exact:true}).click()}
  async function transport(value,cancel=false){
   await parent.getByRole('button',{name:'编辑传输协议',exact:true}).click();
   const dialog=page.getByRole('dialog',{name:'编辑传输协议',exact:true});
   for(const label of ['允许作为入口','作为出口节点','安全性','uTLS 指纹','证书模式','隧道对外地址'])assert.equal(await dialog.getByText(label,{exact:true}).count(),0,label+' leaked into transport dialog');
   await select(dialog,'传输协议',value);
   if(value==='h2'){await input(dialog,'HTTP Path').fill('/custom/stream');await input(dialog,'HTTP Host').fill('stream.example.test');await input(dialog,'连接池上限').fill('3')}
   if(process.env.NEKOPASS_UI_SCREENSHOT_DIR){fs.mkdirSync(process.env.NEKOPASS_UI_SCREENSHOT_DIR,{recursive:true});await dialog.screenshot({path:path.join(process.env.NEKOPASS_UI_SCREENSHOT_DIR,'node-transport-dialog.png')})}
   await dialog.getByRole('button',{name:cancel?'取消':'确定',exact:true}).click();await dialog.waitFor({state:'hidden'});
  }
  async function openSecurity(){await parent.getByRole('button',{name:'安全性设置',exact:true}).click();return page.getByRole('dialog',{name:'安全性设置',exact:true})}
  async function closeSecurity(dialog,cancel=false){await dialog.getByRole('button',{name:cancel?'取消':'确定',exact:true}).click();await dialog.waitFor({state:'hidden'})}
  for(const label of ['入口配置','出口配置','出口监听地址','出口监听端口'])assert.equal(await parent.getByText(label,{exact:true}).isVisible(),true,label);
  assert.equal(await parent.getByText('安全性',{exact:true}).count(),0);
  assert.equal(await parent.getByRole('button',{name:'安全性设置',exact:true}).locator('..').getByRole('button',{name:'编辑传输协议',exact:true}).count(),1);
  assert.equal(await field(parent,'作为出口节点').getByRole('switch').getAttribute('aria-checked'),'false');
  await input(parent,'节点名称').fill('已编辑但未保存');
  await input(parent,'公网隧道端口').fill('32443');
  assert.equal(await input(parent,'入口流量倍率').inputValue(),'1');
  assert.equal(await input(parent,'出口流量倍率').inputValue(),'0');
  await input(parent,'入口流量倍率').fill('0');await input(parent,'出口流量倍率').fill('1.2345');
  await field(parent,'允许作为入口').locator('.el-switch').click();
  let security=await openSecurity();
  await select(security,'安全性','全随机加密');
  for(const label of ['证书模式','uTLS 指纹','连接 SNI（可选）','Fallback 网站地址','TLS Padding'])assert.equal(await security.getByText(label,{exact:true}).count(),0,label+' must be hidden for random encryption');
  await select(security,'加密算法','AES-256-GCM');await input(security,'加密密钥').fill(require('node:crypto').randomBytes(32).toString('base64url'));
  await closeSecurity(security,true);assert.equal(await parent.getByTestId('node-security-summary').innerText(),'不加密');
  security=await openSecurity();await select(security,'安全性','全随机加密');assert.equal(await input(security,'加密密钥').inputValue(),'');
  await select(security,'加密算法','AES-256-GCM');await closeSecurity(security);
  assert.equal(await parent.getByTestId('node-security-summary').innerText(),'全随机加密');
  await parent.getByRole('button',{name:'编辑传输协议',exact:true}).click();
  const randomTransport=page.getByRole('dialog',{name:'编辑传输协议',exact:true});await field(randomTransport,'传输协议').locator('.el-select').click();
  assert.notEqual(await page.getByRole('option',{name:'raw(udp)',exact:true}).getAttribute('aria-disabled'),'true');
  await page.getByRole('option',{name:'raw(udp)',exact:true}).click();await randomTransport.getByRole('button',{name:'确定',exact:true}).click();
  assert.equal(await parent.getByTestId('node-transport-summary').innerText(),'raw(udp)');assert.equal(await parent.getByTestId('node-security-summary').innerText(),'全随机加密');
  security=await openSecurity();assert.match(await field(security,'加密算法').innerText(),/AES-256-GCM/);assert.equal(await security.getByText('TLS Padding',{exact:true}).count(),0);assert.equal(await security.getByText('证书模式',{exact:true}).count(),0);await closeSecurity(security);
  await transport('raw(tcp)');
  security=await openSecurity();assert.match(await field(security,'加密算法').innerText(),/AES-256-GCM/);await select(security,'安全性','不加密');await closeSecurity(security);
  await transport('HTTP/3',true);assert.equal(await parent.getByTestId('node-transport-summary').innerText(),'raw(tcp)');assert.equal(await parent.getByTestId('node-security-summary').innerText(),'不加密');
  await transport('HTTP/3');assert.equal(await parent.getByTestId('node-security-summary').innerText(),'TLS');
  security=await openSecurity();assert.equal(await field(security,'安全性').getByRole('combobox').isDisabled(),true);
  assert.equal(await security.getByText('uTLS 指纹',{exact:true}).count(),0);assert.equal(await security.getByTestId('tls-padding-enabled').count(),0);
  assert.equal(await input(security,'Fallback 网站地址').isVisible(),true);assert.equal(await field(security,'证书模式').isVisible(),true);await closeSecurity(security);
  await transport('raw(tcp)');security=await openSecurity();await select(security,'安全性','不加密');await closeSecurity(security);
  security=await openSecurity();
  for(const label of ['允许作为入口','作为出口节点','出口监听端口','HTTP Path','连接池上限'])assert.equal(await security.getByText(label,{exact:true}).count(),0);
  await select(security,'安全性','TLS');await input(security,'连接 SNI（可选）').fill('cancel.example.test');
  await closeSecurity(security,true);assert.equal(await parent.getByTestId('node-security-summary').innerText(),'不加密');
  security=await openSecurity();await select(security,'安全性','TLS');assert.equal(await input(security,'连接 SNI（可选）').inputValue(),'');
  await select(security,'uTLS 指纹','Chrome（库内预设）');await input(security,'连接 SNI（可选）').fill('override.example.test');
  await security.getByTestId('tls-padding-enabled').click();
  const policy='stop=9\n0=30-30\n1=100-400';
  const padding=dialog=>dialog.locator('textarea[data-testid="tls-padding-scheme"], [data-testid="tls-padding-scheme"] textarea');await padding(security).fill(policy);
  await select(security,'证书模式','DNS 自动申请 / 续期');await field(security,'DNS 凭据 JSON').locator('textarea').fill('{');
  await security.getByRole('button',{name:'确定',exact:true}).click();await page.getByText('DNS 凭据须为 JSON 对象',{exact:true}).waitFor();assert.equal(await security.isVisible(),true);assert.equal(writes.length,0);
  await field(security,'DNS 凭据 JSON').locator('textarea').fill('{"api_token":"fixture"}');
  await input(security,'Fallback 网站地址').fill('https://fallback.example.test');
  await closeSecurity(security);assert.equal(await parent.getByTestId('node-security-summary').innerText(),'TLS');
  await transport('h2',true);assert.equal(await parent.getByTestId('node-transport-summary').innerText(),'raw(tcp)');
  await transport('h2');assert.equal(await parent.getByTestId('node-transport-summary').innerText(),'h2');
  security=await openSecurity();assert.equal(await input(security,'连接 SNI（可选）').inputValue(),'override.example.test');assert.equal(await field(security,'DNS 凭据 JSON').locator('textarea').inputValue(),'{\n  "api_token": "fixture"\n}');assert.equal(await security.getByTestId('tls-padding-enabled').isVisible(),false);await closeSecurity(security,true);
  assert.equal(await input(parent,'节点名称').inputValue(),'已编辑但未保存');assert.equal(writes.length,0);
  await transport('raw(udp)');assert.equal(await parent.getByTestId('node-transport-summary').innerText(),'raw(udp)');
  security=await openSecurity();assert.match(await field(security,'uTLS 指纹').innerText(),/关闭/);assert.equal(await security.getByTestId('tls-padding-enabled').isVisible(),false);await closeSecurity(security,true);
  await transport('raw(tcp)');security=await openSecurity();assert.equal(await padding(security).inputValue(),policy);
  await select(security,'安全性','不加密');assert.equal(await security.getByTestId('tls-padding-enabled').isVisible(),false);await select(security,'安全性','TLS');assert.equal(await padding(security).inputValue(),policy);await closeSecurity(security);
  await transport('h2');security=await openSecurity();await input(security,'连接 SNI（可选）').fill('final.example.test');await closeSecurity(security);
  assert.equal(await input(parent,'公网隧道端口').inputValue(),'32443');assert.equal(writes.length,0,'both child dialogs must only update the parent draft');
  await parent.getByRole('button',{name:'保存并下发',exact:true}).click();await page.getByText('节点配置已保存，密钥可在下方复制',{exact:true}).waitFor();
  assert.equal(writes.length,1);assert.equal(writes[0].endpoint,'/api/v1/admin/nodes/6');
  const body=writes[0].body;assert.equal(body.name,'已编辑但未保存');assert.equal(body.ingress_enabled,false);assert.equal(body.tunnel_exit_enabled,false);assert.equal(body.tunnel_security,'tls');assert.equal(body.tunnel_transport,'h2');
  assert.equal(body.ingress_multiplier,'0');assert.equal(body.egress_multiplier,'1.2345');
  assert.equal(body.tls.client_sni,'final.example.test');assert.equal(body.tls.path,'/custom/stream');assert.equal(body.tls.host,'stream.example.test');assert.equal(body.tls.pool_size,3);assert.equal(body.tls.public_port,32443);assert.equal(body.tls.dns_credentials.api_token,'fixture');assert.equal(body.tls.fallback_url,'https://fallback.example.test');assert.equal(body.tls.padding_enabled,true);assert.deepEqual(body.tls.padding_scheme,policy.split('\n'));
  await parent.getByRole('button',{name:'关闭',exact:true}).click();
  await page.getByRole('button',{name:'添加节点',exact:true}).click();parent=page.getByRole('dialog',{name:'添加节点',exact:true});
  assert.equal(await input(parent,'入口流量倍率').inputValue(),'1');assert.equal(await input(parent,'出口流量倍率').inputValue(),'0');
  await input(parent,'节点名称').fill('新建配置测试');await transport('h2');assert.equal(writes.length,1);assert.equal(await parent.getByTestId('node-security-summary').innerText(),'不加密');
  await parent.getByRole('button',{name:'保存并下发',exact:true}).click();await page.getByText('节点已创建，密钥已填入下方',{exact:true}).waitFor();
  assert.equal(writes.length,2);assert.equal(writes[1].endpoint,'/api/v1/admin/nodes');assert.equal(writes[1].body.tunnel_transport,'h2');assert.equal(writes[1].body.tunnel_security,'none');assert.equal(writes[1].body.tls.path,'/custom/stream');assert.equal(writes[1].body.tunnel_listen_port,0);
  assert.deepEqual(errors,[]);console.log('PASS independent transport/security dialogs, cancel/preserve, scoped settings, DNS validation, atomic edit and create');
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve))}
})().catch(e=>{console.error(e);server.close();process.exitCode=1});
