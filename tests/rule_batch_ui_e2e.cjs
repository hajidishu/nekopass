// Build web first. Requires Playwright on NODE_PATH; NEKOPASS_BROWSER optionally selects a system Chromium.
// Uses a local-only static server and test fixtures; no running panel or real accounts are accessed.
const assert=require('node:assert/strict');
const http=require('node:http');
const fs=require('node:fs');
const path=require('node:path');
const {chromium}=require('playwright');
const root=path.resolve(__dirname,'../web/dist');
const artifacts=path.resolve(process.env.NEKOPASS_E2E_ARTIFACT_DIR||'.local');
fs.mkdirSync(artifacts,{recursive:true});
const server=http.createServer((req,res)=>{
 let name=new URL(req.url,'http://localhost').pathname;
 if(name==='/forward_rules')name='/pages/forward_rules.html';
 if(/^\/admin\/users\/\d+\/forward_rules$/.test(name))name='/pages/admin_user_rules.html';
 const file=path.resolve(root,'.'+name);
 if(!file.startsWith(root+path.sep)||!fs.existsSync(file)||!fs.statSync(file).isFile()){res.writeHead(404);res.end();return}
 const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css','.svg':'image/svg+xml'};
 res.setHeader('Content-Type',types[path.extname(file)]||'application/octet-stream');fs.createReadStream(file).pipe(res);
});
const profile={id:2,username:'fixture@example.test',plan_id:1,plan_name:'fixture',plan_enabled:true,node_ids:[10,11,20],quota_bytes:-1,traffic_bytes:10,max_rules:0,max_connections:0,rule_speed_mbps:0,rule_ip_limit:0,rule_connection_limit:0,rule_count:4,expires_at:null};
const nodes=[{id:10,name:'入口一',deny_udp_ingress_creation:true,ingress_enabled:true,allow_direct:true,tunnel_exit_enabled:false,tunnel_protocol:'plain_tcp',allowed_ingress_ids:[],public_address:'entry.example.test',port_min:1024,port_max:65535},{id:11,name:'入口二',deny_udp_ingress_creation:true,ingress_enabled:true,allow_direct:true,tunnel_exit_enabled:false,tunnel_protocol:'plain_tcp',allowed_ingress_ids:[],public_address:'entry2.example.test',port_min:1024,port_max:65535},{id:20,name:'出口',ingress_enabled:false,allow_direct:false,tunnel_exit_enabled:true,tunnel_protocol:'plain_tcp',allowed_ingress_ids:[10,11],public_address:'exit.example.test'}];
const rules=[1,2,3,4].map(id=>({id,user_id:2,node_id:10,node_name:'入口一',egress_node_id:20,egress_node_name:'出口',protocol:id===3?'udp':'tcp',name:'rule-'+id,listen_port:id===4?443:20000+id,targets:['target.example.test:443'],group_id:0,group_name:'',balance:'random',proxy_accept:'off',proxy_send:'v2',proxy_trusted_cidrs:[],enabled:true,public_address:'entry.example.test',traffic_bytes:100,status:'active',tls_inbound_id:id===4?7:0,sni_names:id===4?['a.example.test']:[],tls_alpn:[],origin_tls:{enabled:false},sync_error:'',speed_mbps:0,ip_limit:0,connection_limit:0}));

(async()=>{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const base='http://127.0.0.1:'+server.address().port;
 const browser=await chromium.launch({headless:true,...(process.env.NEKOPASS_BROWSER?{executablePath:process.env.NEKOPASS_BROWSER}:{})});
 try{
  for(const managed of [false,true]){
   const context=await browser.newContext({viewport:{width:1440,height:1000}});const page=await context.newPage();const calls=[],errors=[];
   page.setDefaultTimeout(15000);page.on('pageerror',e=>errors.push(e.message));
   await page.route('**/api/v1/**',async route=>{
    const url=new URL(route.request().url());const api=url.pathname.slice('/api/v1/'.length);
    if(route.request().method()==='POST'&&api.endsWith('rules/batch')){calls.push({path:api,body:route.request().postDataJSON()});return route.fulfill({json:{ok:true,count:2}})}
    let data={};if(api==='me')data={id:managed?1:2,username:managed?'admin':'fixture@example.test',is_admin:managed};
    else if(api==='profile'||api==='admin/users/2')data=[profile];
    else if(api==='rules'||api==='admin/users/2/rules')data=rules;
    else if(api==='rule-nodes'||api==='admin/users/2/rule-nodes')data=nodes;
    else if(api.endsWith('rule-egress-groups'))data=[{id:20,name:'出口节点组',strategy:'round_robin',node_ids:[20]}];
    else if(api.endsWith('rule-groups')||api.endsWith('tls-inbounds'))data=[];
    else if(api==='site')data={name:'Nekopass',site_name:'Nekopass'};
    await route.fulfill({json:data});
   });
   await page.goto(base+(managed?'/admin/users/2/forward_rules':'/forward_rules'));
   await page.locator('.rules-table .el-table__body-wrapper tbody tr').first().waitFor();
   const rows=()=>page.locator('.rules-table .el-table__body-wrapper tbody tr');
   async function select(indices){for(const index of indices)await rows().nth(index).locator('label.el-checkbox').click()}
   async function open(){await page.getByRole('button',{name:'批量编辑',exact:true}).click();const dlg=page.getByRole('dialog',{name:/批量编辑 \d+ 条规则/});await dlg.waitFor();return dlg}
   async function option(dlg,id,label){await dlg.getByTestId(id).click();await page.getByRole('option',{name:label,exact:true}).click()}
   async function advanced(dlg){await dlg.getByText('高级选项（留空不更新）',{exact:true}).click()}
   // New rules cannot select UDP on a restricted ingress. Existing UDP edits remain allowed.
   const field=(dialog,label)=>dialog.getByText(label,{exact:true}).locator('..');
   async function selectField(dialog,label,value){await field(dialog,label).locator('.el-select').click();await page.getByRole('option',{name:value,exact:true}).click()}
   async function inspectUDP(dialog,disabled){await field(dialog,'转发类型').locator('.el-select').click();assert.equal(await page.getByRole('option',{name:'UDP',exact:true}).getAttribute('aria-disabled')==='true',disabled);await page.getByRole('option',{name:'TCP',exact:true}).click()}
   async function cancelRule(dialog){await dialog.getByRole('button',{name:'取消',exact:true}).click();await dialog.waitFor({state:'hidden'})}
   await page.getByRole('button',{name:'添加规则',exact:true}).click();let ruleDialog=page.getByRole('dialog',{name:'添加规则',exact:true});
   await selectField(ruleDialog,'入口','入口一');await inspectUDP(ruleDialog,true);await cancelRule(ruleDialog);
   await rows().nth(0).getByRole('button',{name:'编辑规则',exact:true}).click();ruleDialog=page.getByRole('dialog',{name:'编辑规则',exact:true});await inspectUDP(ruleDialog,true);await cancelRule(ruleDialog);
   await rows().nth(2).getByRole('button',{name:'编辑规则',exact:true}).click();ruleDialog=page.getByRole('dialog',{name:'编辑规则',exact:true});await inspectUDP(ruleDialog,false);await cancelRule(ruleDialog);
   await rows().nth(2).getByRole('button',{name:'复制规则',exact:true}).click();ruleDialog=page.getByRole('dialog',{name:'添加规则',exact:true});
   await ruleDialog.getByRole('button',{name:'确定',exact:true}).click();await page.getByText('此节点禁止创建新的 UDP 入站规则，请选择其他入口',{exact:true}).waitFor();assert.equal(calls.length,0);await cancelRule(ruleDialog);
   await select([0,1]);let dlg=await open();
   await option(dlg,'batch-rule-egress','#0 不使用隧道，直接转发');
   await option(dlg,'batch-rule-ingress','入口二');
   await dlg.getByTestId('batch-rule-ingress').hover();await dlg.getByTestId('batch-rule-ingress').locator('.el-select__clear').click();
   await advanced(dlg);await option(dlg,'batch-rule-balance','轮询');await option(dlg,'batch-rule-proxy-send','关闭');
   // A normal page refresh must not change the IDs captured by the modal.
   await page.waitForTimeout(5100);
   if(!managed)await page.screenshot({path:path.join(artifacts,'rule-batch-dialog-desktop.png'),fullPage:true});
   await dlg.getByRole('button',{name:'确定',exact:true}).click();await dlg.waitFor({state:'hidden'});
   assert.deepEqual(calls.at(-1),{path:managed?'admin/users/2/rules/batch':'rules/batch',body:{ids:[1,2],action:'edit',patch:{egress_node_id:0,balance:'round_robin',proxy_send_enabled:false}}});
   await select([0,1]);dlg=await open();const previous=calls.length;
   await dlg.getByRole('button',{name:'确定',exact:true}).click();await page.getByText('请选择至少一个需要更新的字段',{exact:true}).waitFor();assert.equal(calls.length,previous);
   await dlg.getByRole('button',{name:'暂停选中规则',exact:true}).click();await dlg.waitFor({state:'hidden'});
   assert.deepEqual(calls.at(-1).body,{ids:[1,2],action:'disable'});
   await select([0,2]);dlg=await open();
   await dlg.getByTestId('batch-rule-ingress').click();
   assert.equal(await page.getByRole('option',{name:'入口二（禁止新增 UDP 入站）',exact:true}).getAttribute('aria-disabled'),'true');
   assert.notEqual(await page.getByRole('option',{name:'入口一',exact:true}).getAttribute('aria-disabled'),'true');
   await page.getByRole('option',{name:'入口一',exact:true}).click();
   await dlg.getByTestId('batch-rule-ingress').hover();await dlg.getByTestId('batch-rule-ingress').locator('.el-select__clear').click();
   await advanced(dlg);await dlg.getByTestId('batch-rule-proxy-send').click();
   const enabled=page.getByRole('option',{name:'开启',exact:true});assert.equal(await enabled.getAttribute('aria-disabled'),'true');
   await page.getByRole('option',{name:'关闭',exact:true}).click();await dlg.getByRole('button',{name:'确定',exact:true}).click();await dlg.waitFor({state:'hidden'});
   assert.deepEqual(calls.at(-1).body,{ids:[1,3],action:'edit',patch:{proxy_send_enabled:false}});
   await select([3]);dlg=await open();assert.equal(await dlg.getByTestId('batch-rule-ingress').locator('input').first().isDisabled(),true);
   await advanced(dlg);assert.equal(await dlg.getByTestId('batch-rule-proxy-accept').locator('input').first().isDisabled(),true);
   await option(dlg,'batch-rule-balance','最少连接');await dlg.getByRole('button',{name:'确定',exact:true}).click();await dlg.waitFor({state:'hidden'});
   assert.deepEqual(calls.at(-1).body,{ids:[4],action:'edit',patch:{balance:'least_connections'}});
   await select([0,1]);dlg=await open();await option(dlg,'batch-rule-egress','出口节点组');
   assert.equal(await dlg.getByTestId('batch-rule-egress').locator('.is-group .ui-icon').count(),1);
   await dlg.getByRole('button',{name:'确定',exact:true}).click();await dlg.waitFor({state:'hidden'});
   assert.deepEqual(calls.at(-1).body,{ids:[1,2],action:'edit',patch:{egress_group_id:20}});
   assert.deepEqual(errors,[]);console.log('PASS browser batch edit, zero/false, clear/omit, polling, pause, mixed UDP, shared TLS; managed='+managed);
   await context.close();
  }
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve))}
})().catch(err=>{console.error(err);server.close();process.exitCode=1});
