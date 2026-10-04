// Run against the dedicated HTTP test panel with Playwright available on NODE_PATH.
// NEKOPASS_E2E_BASE is the panel origin; NEKOPASS_E2E_ADMIN_FILE contains
// {username,password}; NEKOPASS_BROWSER optionally selects a Chromium executable.
const {chromium}=require('playwright');
const fs=require('fs');
(async()=>{
 const base=process.env.NEKOPASS_E2E_BASE||'http://127.0.0.1:8080';
 const access=JSON.parse(fs.readFileSync(process.env.NEKOPASS_E2E_ADMIN_FILE||'.local/test-access.json','utf8'));
 const browser=await chromium.launch({headless:true,...(process.env.NEKOPASS_BROWSER?{executablePath:process.env.NEKOPASS_BROWSER}:{})});
 async function submit(page){
  await page.locator('input[autocomplete="username"]').fill(access.username);
  await page.locator('input[autocomplete="current-password"]').fill(access.password);
  await page.getByRole('button',{name:'登录',exact:true}).click();
 }
 try {
  for(const secure of [false,true]){
   const context=await browser.newContext();
   try {
    if(secure)await context.addCookies([{name:'nekopass_session',value:'old-https-session',domain:new URL(base).hostname,path:'/',secure:true,httpOnly:true,sameSite:'Strict'}]);
    const page=await context.newPage();await page.goto(base+'/forward_rules');
    await page.waitForURL(/\/login\?next=/);await submit(page);
    await page.waitForURL(base+'/forward_rules');await page.locator('.rules-panel').waitFor();
    const me=await context.request.get(base+'/api/v1/me');if(me.status()!==200)throw new Error('session missing after login');
    const cookie=(await context.cookies()).find(c=>c.name==='nekopass_session_http');
    if(!cookie||cookie.secure||!cookie.httpOnly)throw new Error('invalid HTTP session cookie');
    await context.request.post(base+'/api/v1/logout',{data:{}});
    await page.goto(base+'/forward_rules');await page.waitForURL(/\/login\?next=/);
    if((await context.request.get(base+'/api/v1/me')).status()!==401)throw new Error('logout did not revoke session');
    console.log('PASS HTTP deep-link login and logout; old Secure cookie='+secure);
   }finally{await context.close()}
  }
  const context=await browser.newContext();
  try{
   const page=await context.newPage();
   // Simulate credentials accepted but the browser refusing to store the cookie.
   await page.route('**/api/v1/login',r=>r.fulfill({json:{id:1,username:'fixture',is_admin:true}}));
   await page.goto(base+'/login');await submit(page);
   await page.getByText('登录状态未能保存，请确认浏览器允许本站 Cookie 后重试。',{exact:true}).waitFor();
   if(new URL(page.url()).pathname!=='/login')throw new Error('redirected without a session');
   console.log('PASS explicit error when session cookie is not stored');
  }finally{await context.close()}
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exit(1)});
