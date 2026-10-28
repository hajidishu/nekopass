// Build web first. All API data is supplied by fixtures.
const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const http=require('node:http'),fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'../web/dist');
const server=http.createServer((req,res)=>{
 let name=new URL(req.url,'http://localhost').pathname;if(name==='/node_status')name='/pages/node_status.html';
 const file=path.resolve(root,'.'+name);if(!file.startsWith(root+path.sep)||!fs.existsSync(file)){res.writeHead(404);res.end();return}
 res.setHeader('Content-Type',({'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css','.svg':'image/svg+xml'})[path.extname(file)]||'application/octet-stream');fs.createReadStream(file).pipe(res);
});
(async()=>{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;
 try{
  browser=await chromium.launch({headless:true,...(process.env.NEKOPASS_BROWSER?{executablePath:process.env.NEKOPASS_BROWSER}:{})});
  const page=await browser.newPage({viewport:{width:1440,height:1050}}),errors=[];page.on('pageerror',e=>errors.push(e.message));
  let cpu=25,historyRequests=0,activeHistory=0,maxHistory=0;
  const makeNode=()=>({id:6,name:'探针测试节点',group_id:1,group_name:'测试节点组',enabled:true,online:true,updated_at:new Date().toISOString(),last_report_at:new Date().toISOString(),first_connected_at:'2026-10-01T00:00:00Z',uptime_seconds:90061,uptime_ready:true,traffic_ready:true,traffic_today_rx_bytes:2*1024**3,traffic_today_tx_bytes:3*1024**3,traffic_30d_rx_bytes:20*1024**3,traffic_30d_tx_bytes:30*1024**3,metrics:{sampled_at:Math.floor(Date.now()/1000),cpu_ready:true,cpu_percent:cpu,memory_ready:true,memory_total:4*1024**3,memory_used:2*1024**3,disk_ready:true,disk_total:50*1024**3,disk_used:25*1024**3,network_ready:true,rx_mbps:12.5,tx_mbps:18.75,disk_io_ready:true,disk_read_bytes_per_second:2e6,disk_write_bytes_per_second:3e9,disk_device:'vda',connections_ready:true,tcp_connections:100,udp_sockets:10,load_ready:true,load1:0.5,load5:0.25,load15:0.1}});
  await page.route('**/api/v1/**',async route=>{
   const endpoint=new URL(route.request().url()).pathname;
   if(endpoint.endsWith('/me'))return route.fulfill({json:{id:2,username:'fixture',is_admin:false}});
   if(/\/node-status\/\d+\/history$/.test(endpoint)){
    historyRequests++;activeHistory++;maxHistory=Math.max(maxHistory,activeHistory);
    await new Promise(resolve=>setTimeout(resolve,100));activeHistory--;
    const id=Number(endpoint.split('/').at(-2));
    return route.fulfill({json:id===13?[]:Array.from({length:20},(_,i)=>({at:Math.floor(Date.now()/1000)-100+i*5,cpu:10+i,memory:35+i/2,disk:50,disk_read:1e6+i*1e5,disk_write:2e6+i*2e5}))});
   }
   if(endpoint.endsWith('/node-status')){
    const node=makeNode();
    if(cpu===72){node.metrics.disk_read_bytes_per_second=8e6;node.metrics.disk_write_bytes_per_second=1e9}
    const others=Array.from({length:7},(_,i)=>({...node,id:7+i,name:'其他节点'+i,...(i===6?{online:false,metrics:null,traffic_ready:false}:{})}));
    return route.fulfill({json:[node,{...node,group_id:2,group_name:'第二个节点组'},...others]});
   }
   return route.fulfill({json:{site_name:'Nekopass'}});
  });
  await page.goto('http://127.0.0.1:'+server.address().port+'/node_status');
  const card=page.locator('[data-node-id="6"]').first();await card.waitFor();
  for(const text of ['今日','近 30 天','3.00 GiB','2.00 GiB','30.00 GiB','20.00 GiB','2.00 MB/s','3.00 GB/s','最后上报','首次上线','已运行'])assert.equal(await card.getByText(text,{exact:true}).isVisible(),true,text);
  for(const kind of ['cpu','memory','disk','io'])await card.getByTestId('probe-chart-'+kind).getByRole('img').waitFor();
  assert.equal(await card.locator('.el-progress').count(),0,'progress bars should be replaced');
  const chart=card.getByTestId('probe-chart-cpu');
  await page.waitForFunction(()=>document.querySelector('[data-node-id="6"] [data-series="cpu"]')?.getAttribute('d').includes('L'));
  const original=await chart.locator('[data-series="cpu"]').getAttribute('d');
  const io=card.getByTestId('probe-chart-io');
  assert.equal(await io.locator('[data-series]').count(),2);
  const originalRead=await io.locator('[data-series="disk_read"]').getAttribute('d');
  assert.ok(maxHistory<=4,'history requests exceeded concurrency limit');
  cpu=72;
  await page.waitForFunction(()=>document.querySelector('[data-node-id="6"] .probe-meter-heading strong').textContent.includes('72.00%'));
  assert.notEqual(await chart.locator('[data-series="cpu"]').getAttribute('d'),original,'inline CPU trend did not update');
  assert.notEqual(await io.locator('[data-series="disk_read"]').getAttribute('d'),originalRead,'I/O trend did not update');
  assert.equal(historyRequests,8,'charts and duplicate node-group cards should share one history request per node');
  assert.ok(maxHistory<=4,'history requests exceeded concurrency limit');
  assert.equal(await page.locator('[data-node-id="13"] [data-series]').count(),0,'missing samples should not be shown as zero');
  fs.mkdirSync(path.resolve(__dirname,'../.local/probe-ui'),{recursive:true});
  await page.setViewportSize({width:1440,height:1600});
  await page.evaluate(()=>window.scrollTo(0,0));
  await card.screenshot({path:path.resolve(__dirname,'../.local/probe-ui/desktop.png')});
  await page.mouse.move(0,0);await page.setViewportSize({width:390,height:1600});
  await page.waitForFunction(()=>document.querySelector('.sidebar').getBoundingClientRect().right<=1);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'mobile overflow');
  await card.screenshot({path:path.resolve(__dirname,'../.local/probe-ui/mobile.png')});
  assert.deepEqual(errors,[]);
  console.log('PASS inline resource and dual-line disk trends, shared bounded history loading, live updates and mobile layout');
 }finally{if(browser)await browser.close();await new Promise(resolve=>server.close(resolve))}
})().catch(e=>{console.error(e);process.exitCode=1});
