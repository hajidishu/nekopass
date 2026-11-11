// Build web first; cloud credentials and instance records are browser fixtures.
const {chromium}=require('playwright');
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),http=require('node:http');
const root=path.resolve(__dirname,'../web/dist'),writes=[];
const config={enabled:false,target_ip:'',failure_threshold:6,cooldown_seconds:300,instance_type:'ec2',binding_mode:'instance',profile_id:'',auth_token:'',share_group_token:'',account_id:'',region_name:'',instance_id:'',static_ip:false};
let reads=0,protocol=35;
const server=http.createServer((req,res)=>{
 const p=new URL(req.url,'http://localhost').pathname,json=data=>{res.setHeader('Content-Type','application/json');res.end(JSON.stringify(data))};
 if(p==='/api/v1/admin/nodes/6/ip-recovery'){
  if(req.method==='PUT'){let body='';req.on('data',v=>body+=v);req.on('end',()=>{writes.push(JSON.parse(body));Object.assign(config,writes.at(-1));json({generation:writes.length})});return}
  reads++;json({node_id:6,node_name:'测试节点',protocol_version:protocol,online:true,config,generation:1,status:{state:'healthy',checked_unix:1800000000,reachable:true,failures:0,instance_id:'i-current',region_name:'ap-southeast-1'}});return;
 }
 if(p==='/api/v1/me'){json({id:1,username:'fixture-admin',is_admin:true});return}
 if(p==='/api/v1/site'){json({site_name:'Nekopass'});return}
 const file=path.resolve(root,p==='/admin/nodes/6/ip-recovery'?'pages/admin_node_ip_recovery.html':'.'+p);
 if(!file.startsWith(root+path.sep)||!fs.existsSync(file)){res.writeHead(404);res.end();return}
 res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.svg')?'image/svg+xml':'text/html');fs.createReadStream(file).pipe(res);
});
(async()=>{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));let browser;
 try{
  browser=await chromium.launch({headless:true,...(process.env.NEKOPASS_BROWSER?{executablePath:process.env.NEKOPASS_BROWSER}:{})});
  const page=await browser.newPage({viewport:{width:1440,height:1100}}),errors=[];page.on('pageerror',e=>errors.push(e.message));
  const field=label=>page.locator('.el-form-item').filter({has:page.locator('.el-form-item__label').getByText(label,{exact:true})});
  const select=async(label,option)=>{await field(label).locator('.el-select').click();await page.getByRole('option',{name:option,exact:true}).click()};
  const save=async()=>{const saved=page.waitForResponse(r=>r.url().endsWith('/api/v1/admin/nodes/6/ip-recovery')&&r.request().method()==='PUT');await page.getByRole('button',{name:'保存并下发',exact:true}).click();await saved};
  await page.goto('http://127.0.0.1:'+server.address().port+'/admin/nodes/6/ip-recovery');await field('国内检测 IPv4').locator('input').waitFor();
  await field('启用自动换 IP').locator('.el-switch').click();
  await field('国内检测 IPv4').locator('input').fill('1.1.1.1');
  await field('小助理账号 ID').locator('input').fill('fixture-account');await field('地区').locator('input').fill('ap-southeast-1');await field('EC2 实例 ID').locator('input').fill('i-fixture');
  await field('分享组 Token').locator('input').fill('fixture-share-token');
  await save();assert.equal(writes[0].binding_mode,'instance');assert.equal(writes[0].instance_id,'i-fixture');
  await select('绑定方式','跟随档案 ID');
  assert.equal(await field('小助理账号 ID').count(),0);assert.equal(await field('地区').count(),0);assert.equal(await field('EC2 实例 ID').count(),0);
  await field('实例档案 ID').locator('input').fill('fixture-profile');
  await page.getByText('此节点需要升级后才能使用档案绑定；升级前不会执行自动换 IP。',{exact:true}).waitFor();
  const before=reads;protocol=36;await page.waitForFunction(()=>!document.body.textContent.includes('此节点需要升级后才能使用档案绑定'),{},{timeout:10000});assert.ok(reads>before);
  assert.equal(await field('实例档案 ID').locator('input').inputValue(),'fixture-profile','poll discarded profile draft');
  assert.equal(await field('分享组 Token').locator('input').inputValue(),'fixture-share-token','poll discarded sharing credential');
  await save();assert.equal(writes[1].binding_mode,'profile');assert.equal(writes[1].profile_id,'fixture-profile');assert.equal(writes[1].share_group_token,'fixture-share-token');
  await page.reload();await field('实例档案 ID').locator('input').waitFor();assert.equal(await field('实例档案 ID').locator('input').inputValue(),'fixture-profile');
  assert.equal(await page.getByText('i-current',{exact:true}).count(),1);
  await select('绑定方式','固定实例 ID');assert.equal(await field('EC2 实例 ID').locator('input').inputValue(),'i-fixture');
  await select('实例类型','Lightsail');await field('Lightsail 实例名称').locator('input').waitFor();
  await select('绑定方式','跟随档案 ID');assert.equal(await field('实例档案 ID').locator('input').inputValue(),'fixture-profile');
  await save();assert.equal(writes[2].instance_type,'lightsail');assert.equal(writes[2].binding_mode,'profile');
  await page.setViewportSize({width:390,height:844});await page.waitForFunction(()=>document.querySelector('.sidebar').getBoundingClientRect().right<=1);assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'mobile page overflow');
  assert.deepEqual(errors,[]);console.log('PASS fixed/profile selection, sharing payload, old-agent guard, poll draft preservation, saved reload, Lightsail and mobile layout');
 }finally{if(browser)await browser.close();server.closeAllConnections();await new Promise(r=>server.close(r))}
})().catch(e=>{console.error(e);process.exitCode=1});
