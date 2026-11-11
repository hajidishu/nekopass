// Build web first. Synthetic data is confined to this local browser fixture.
const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const http=require('node:http'),fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'../web/dist');
const pages={'/admin':'admin','/admin/nodes':'admin_nodes','/admin/users':'admin_users','/admin/announcements':'admin_announcements','/admin/tickets':'admin_tickets','/admin/orders':'admin_orders'};
const server=http.createServer((req,res)=>{
 const name=new URL(req.url,'http://localhost').pathname,file=path.resolve(root,'.'+(pages[name]?'/pages/'+pages[name]+'.html':name));
 if(!file.startsWith(root+path.sep)||!fs.existsSync(file)){res.writeHead(404);res.end();return}
 res.setHeader('Content-Type',({'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css','.svg':'image/svg+xml'})[path.extname(file)]||'application/octet-stream');fs.createReadStream(file).pipe(res);
});

(async()=>{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;
 try{
  browser=await chromium.launch({headless:true,...(process.env.NEKOPASS_BROWSER?{executablePath:process.env.NEKOPASS_BROWSER}:{})});
  const page=await browser.newPage({viewport:{width:1720,height:1080}}),errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.addInitScript(()=>localStorage.setItem('nekopass-theme-v3','dark'));
  let revision=0,active=0,maxActive=0,empty=false;const ranges=[],requests=[];
  function dashboard(range){
   const now=Date.now(),at=Math.floor(now/1000),day=Math.floor((at+28800)/86400)*86400-28800;
   const metrics={sampled_at:at,cpu_ready:true,cpu_percent:18.4,memory_ready:true,memory_total:4*1024**3,memory_used:2*1024**3,disk_ready:true,disk_total:40*1024**3,disk_used:10*1024**3,network_ready:true,rx_mbps:388.1,tx_mbps:426.8,uptime_ready:true,uptime_seconds:12*86400};
   return {generated_at:new Date(now+revision).toISOString(),timezone:'Asia/Shanghai',range,unit:range==='24h'?'mbps':'bytes',stats:{users:1284+revision,new_users:12,nodes:20,enabled_nodes:20,online_nodes:18,offline_nodes:2,rules:312,connections:8642,recharge_cents:128000,recharge_orders:24,waiting_tickets:empty?0:3,high_tickets:empty?0:1,medium_tickets:empty?0:1,low_tickets:empty?0:1,today_rx:864*1024**3,today_tx:1.02*1024**4,traffic_ready:!empty},traffic:empty?[]:Array.from({length:range==='24h'?25:range==='7d'?7:30},(_,i)=>({at:range==='24h'?Math.floor(at/3600)*3600-(24-i)*3600:day-((range==='7d'?6:29)-i)*86400,rx:range==='24h'?200+i*15+Math.sin(i)*90:(i+1)*1024**3,tx:range==='24h'?100+i*9+Math.sin(i)*40:(i+2)*1024**3})),nodes:empty?[]:['香港 01','香港 02','东京 01','新加坡 01','洛杉矶 01'].map((name,i)=>({id:i+1,name,enabled:true,online:i!==1,metrics:i===1?null:{...metrics,cpu_percent:18+i*9},history:Array.from({length:20},(_,j)=>({at:at-100+j*5,cpu:15+i*9+j/4+Math.sin(j)*3,memory:50+i+j/6,disk:25,disk_read:0,disk_write:0}))})),orders:empty?[]:[['recharge',10000,'paid'],['purchase',6000,'paid'],['renewal',12000,'paid'],['recharge',20000,'pending']].map((v,i)=>({id:i+1,order_no:'R-fixture-'+i,user_id:1024-i,username:'用户 #'+(1024-i),kind:v[0],amount_cents:v[1],status:v[2],created_at:new Date(now-i*3600000).toISOString()})),host:{...metrics,cpu_percent:12.6,memory_total:2*1024**3,memory_used:834*1024**2}};
  }
  await page.route('**/api/v1/**',async route=>{
   const url=new URL(route.request().url()),endpoint=url.pathname;requests.push(url.pathname+url.search);
   if(endpoint.endsWith('/me'))return route.fulfill({json:{id:1,username:'管理员',is_admin:true}});
   if(endpoint.endsWith('/admin/dashboard')){
    const range=url.searchParams.get('range')||'24h';ranges.push(range);active++;maxActive=Math.max(maxActive,active);await new Promise(r=>setTimeout(r,80));const data=dashboard(range);active--;return route.fulfill({json:data});
   }
   if(endpoint.endsWith('/admin/nodes'))return route.fulfill({json:[{id:1,name:'在线节点',enabled:true,online:true,public_address:'example.test',group_ids:[],allowed_ingress_ids:[],network_interfaces:[],tunnel_security:'none',update_status:null,update_supported:true,agent_version:'dev',sync_error:'',applied_revision:1,config_revision:1,ingress_enabled:true,port_min:1024,port_max:65535},{id:2,name:'离线节点',enabled:true,online:false,group_ids:[],allowed_ingress_ids:[],network_interfaces:[],tunnel_security:'none',update_status:null,sync_error:'',applied_revision:1,config_revision:1,port_min:1024,port_max:65535}]});
   if(endpoint.endsWith('/admin/announcements')||endpoint.endsWith('/admin/tickets'))return route.fulfill({json:{items:[],total:0,page:1}});
   if(endpoint.endsWith('/admin/users')||endpoint.endsWith('/admin/plans')||endpoint.endsWith('/admin/node-groups'))return route.fulfill({json:[]});
   return route.fulfill({json:{site_name:'Nekopass'}});
  });
  const base='http://127.0.0.1:'+server.address().port;
  await page.goto(base+'/admin');await page.getByTestId('admin-overview').waitFor();
  for(const text of ['后台概览','全网流量','待处理工单','节点概况','最近订单','面板主机'])assert.equal(await page.getByText(text,{exact:true}).isVisible(),true,text);
  assert.equal(await page.locator('.dashboard-stat').count(),4);
  assert.ok((await page.getByTestId('dashboard-recharge').innerText()).includes('1,280.00'));
  const recharge=new URL(await page.getByTestId('dashboard-recharge').getAttribute('href'),base);assert.equal(recharge.searchParams.get('time_field'),'paid');assert.ok(recharge.searchParams.has('from'));
  assert.equal(await page.locator('.sidebar-pending-count').innerText(),'3');
  await page.locator('[data-testid="dashboard-traffic-chart"] [data-series="rx"]').waitFor();
  await page.getByRole('button',{name:'7 天',exact:true}).click();await page.waitForFunction(()=>document.querySelector('.dashboard-chart-legend')?.textContent.includes('每日累计流量'));
  await page.getByRole('button',{name:'30 天',exact:true}).click();await page.waitForTimeout(200);await page.getByRole('button',{name:'24 小时',exact:true}).click();await page.waitForTimeout(200);
  assert.ok(ranges.includes('7d')&&ranges.includes('30d'));assert.equal(maxActive,1);
  revision=1;await page.getByRole('button',{name:'刷新',exact:true}).click();await page.waitForFunction(()=>document.querySelector('[data-testid="dashboard-users"]')?.textContent.includes('1,285'));
  const tickets=page.getByTestId('dashboard-tickets');
  assert.equal(await tickets.locator('.dashboard-count').innerText(),'3');
  assert.equal(await tickets.getByText('离线节点',{exact:true}).count(),0);
  assert.equal(await tickets.getByText('DDNS 异常',{exact:true}).count(),0);
  assert.equal(await tickets.getByText('快捷操作',{exact:true}).count(),0);
  for(const [priority,label]of [['high','高优先级'],['medium','中优先级'],['low','低优先级']])assert.ok((await tickets.getByRole('link',{name:new RegExp(label)}).getAttribute('href')).includes('priority='+priority));
  const output=path.resolve(__dirname,'../.local/dashboard-preview');fs.mkdirSync(output,{recursive:true});
  await page.screenshot({path:path.join(output,'desktop-dark.png'),fullPage:true});
  await page.getByRole('button',{name:'切换浅色模式'}).click();await page.waitForTimeout(220);await page.screenshot({path:path.join(output,'desktop-light.png'),fullPage:true});
  await page.setViewportSize({width:390,height:1080});await page.waitForFunction(()=>document.querySelector('.sidebar').getBoundingClientRect().right<=1);assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'mobile page overflow');await page.screenshot({path:path.join(output,'mobile.png'),fullPage:true});
  await page.setViewportSize({width:320,height:1080});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'small mobile page overflow');
  await page.setViewportSize({width:1440,height:1000});
  empty=true;await page.getByRole('button',{name:'刷新',exact:true}).click();await page.getByText('等待流量采样',{exact:true}).waitFor();await page.getByText('暂无订单',{exact:true}).waitFor();await page.getByText('暂无待处理工单',{exact:true}).waitFor();empty=false;
  await page.goto(base+'/admin/nodes?status=offline');await page.getByText('仅显示已启用的离线节点',{exact:false}).waitFor();assert.equal(await page.locator('.el-table__body-wrapper').getByText('在线节点',{exact:true}).count(),0);await page.getByRole('button',{name:'显示全部节点'}).click();await page.locator('.el-table__body-wrapper').getByText('在线节点',{exact:true}).waitFor();
  for(const target of ['nodes','users','announcements']){await page.goto(base+'/admin/'+target+'?create=1');const dialog=page.getByRole('dialog');await dialog.waitFor();assert.equal(new URL(page.url()).searchParams.has('create'),false,'create shortcut was not consumed');await page.getByRole('button',{name:'取消',exact:true}).count().then(async n=>{if(n)await page.getByRole('button',{name:'取消',exact:true}).last().click()})}
  await page.goto(base+'/admin/tickets?status=waiting_staff&priority=high');await page.getByText('暂无工单',{exact:true}).waitFor();assert.ok(requests.some(p=>p.includes('/admin/tickets?page=1&status=waiting_staff&priority=high')));
  assert.deepEqual(errors,[]);console.log('PASS dashboard data, live refresh, range controls, dark/light/mobile layout, empty states, and actionable shortcuts');
 }finally{if(browser)await browser.close();await new Promise(r=>server.close(r))}
})().catch(e=>{console.error(e);process.exitCode=1});
