// Build web first. Requests use fixtures and never contact Cloudflare.
const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const http=require('node:http');
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'../web/dist');
const server=http.createServer((req,res)=>{
 let name=new URL(req.url,'http://localhost').pathname;
 if(name==='/admin/nodes/6/ddns')name='/pages/admin_node_ddns.html';
 const file=path.resolve(root,'.'+name);
 if(!file.startsWith(root+path.sep)||!fs.existsSync(file)){res.writeHead(404);res.end();return}
 res.setHeader('Content-Type',({'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css','.svg':'image/svg+xml'})[path.extname(file)]||'application/octet-stream');
 fs.createReadStream(file).pipe(res);
});
(async()=>{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 let browser;
 try{
  browser=await chromium.launch({headless:true,...(process.env.NEKOPASS_BROWSER?{executablePath:process.env.NEKOPASS_BROWSER}:{})});
  // Simulate an existing configuration without the new fields.
  let saved={enabled:true,provider:'cloudflare',record_name:'node.example.test',zone_id:'',token:'fixture-token',ipv4:true,ipv6:true,interval_seconds:300,ttl:300,ipv4_url:'https://ip4.example.test',ipv6_url:'https://ip6.example.test',use_for_ingress:true,use_for_egress:true};
  let version=30;
  const writes=[],errors=[];
  const page=await browser.newPage();page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/api/v1/**',async route=>{
   const request=route.request(),endpoint=new URL(request.url()).pathname;
   if(endpoint.endsWith('/me'))return route.fulfill({json:{id:1,username:'fixture',is_admin:true}});
   if(endpoint.endsWith('/ddns')){
    if(request.method()==='PUT'){saved=request.postDataJSON();writes.push(structuredClone(saved));return route.fulfill({json:{generation:2}})}
    return route.fulfill({json:{node_id:6,node_name:'DDNS 测试节点',protocol_version:version,online:true,config:saved,generation:1,status:{state:'ok'},status_received_at:null}});
   }
   return route.fulfill({json:{site_name:'Nekopass'}});
  });
  const field=label=>page.getByText(label,{exact:true}).locator('..');
  async function selectSource(label){await field('IP 获取方式').locator('.el-select').click();await page.getByRole('option',{name:label,exact:true}).click()}
  const filter=page.getByRole('checkbox',{name:'忽略内网 IP 和回环地址',exact:true});
  const filterLabel=page.locator('.el-checkbox').filter({hasText:'忽略内网 IP 和回环地址'});
  await page.goto('http://127.0.0.1:'+server.address().port+'/admin/nodes/6/ddns');
  await page.getByText('IPv4 获取地址',{exact:true}).waitFor();
  assert.equal(await filterLabel.isVisible(),false);
  await selectSource('通过网卡获取');
  assert.equal(await filter.isChecked(),true);
  assert.equal(await page.getByText('IPv4 获取地址',{exact:true}).isVisible(),false);
  assert.equal(await page.getByText('IPv6 获取地址',{exact:true}).isVisible(),false);
  await filterLabel.click();assert.equal(await filter.isChecked(),false);
  const persisted=page.waitForResponse(r=>r.request().method()==='PUT'&&r.url().endsWith('/ddns'));
  await page.getByRole('button',{name:'保存并下发',exact:true}).click();await persisted;
  assert.equal(writes[0].ip_source,'interface');assert.equal(writes[0].ignore_private_ips,false);
  assert.equal(writes[0].ipv4_url,'https://ip4.example.test');
  await page.reload();await filterLabel.waitFor();
  assert.equal(await filter.isChecked(),false);
  await selectSource('通过公网 API 查询');
  assert.equal(await filterLabel.isVisible(),false);
  assert.equal(await field('IPv4 获取地址').locator('input').inputValue(),'https://ip4.example.test');
  assert.equal(await field('IPv6 获取地址').locator('input').inputValue(),'https://ip6.example.test');
  await selectSource('通过网卡获取');assert.equal(await filter.isChecked(),false);
  version=29;await page.reload();
  await page.getByText('请先升级节点端，再使用通过网卡获取 IP。',{exact:true}).waitFor();
  assert.deepEqual(errors,[]);
  console.log('PASS DDNS source switching, filter persistence, legacy defaults and upgrade feedback');
 }finally{if(browser)await browser.close();await new Promise(resolve=>server.close(resolve))}
})().catch(error=>{console.error(error);process.exitCode=1});
