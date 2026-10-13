const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require(process.env.PLAYWRIGHT_NODE_MODULES ? path.join(process.env.PLAYWRIGHT_NODE_MODULES,'playwright') : 'playwright');

(async () => {
  const passwordFile = process.env.ION_SMOKE_PASSWORD_FILE || process.argv[2];
  if (!passwordFile) throw new Error('Provide ION_SMOKE_PASSWORD_FILE or a password file argument.');
  const base = process.env.ION_SMOKE_BASE_URL || 'http://127.0.0.1:8820';
  const options = {headless:true};
  if (process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE) options.executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE;
  const browser = await chromium.launch(options);
  try {
    const page = await browser.newPage({viewport:{width:1440,height:1000}});
    if(process.env.ION_SMOKE_PROVE_OLD_FAILURE) {
      const previous=fs.readFileSync('src/ion/web/static/js/detection-engineering.js','utf8').replace('if (!success) showFailure();',"if (!success) deMessage(target, 'Unable to load this panel. Refresh to try again.');");
      await page.route('**/static/js/detection-engineering.js*',route=>route.fulfill({status:200,contentType:'application/javascript',body:previous}));
    }
    const errors=[];
    const catalogueReads={d3fend:0,emulation:0,vulns:0};
    page.on('request',request=>{
      const name=new URL(request.url()).pathname.split('/').pop();
      if(request.url().includes('/ui/detection-engineering/') && name in catalogueReads) catalogueReads[name]++;
    });
    page.on('pageerror', error=>errors.push(error.message));
    await page.addInitScript(() => {
      window.deListenerBalance=0;
      const add=document.addEventListener.bind(document), remove=document.removeEventListener.bind(document);
      document.addEventListener=(name,callback,...args)=>{if(name==='htmx:afterRequest')window.deListenerBalance++;return add(name,callback,...args);};
      document.removeEventListener=(name,callback,...args)=>{if(name==='htmx:afterRequest')window.deListenerBalance--;return remove(name,callback,...args);};
    });
    await page.goto(base+'/login');
    await page.locator('#username').fill(process.env.ION_SMOKE_USERNAME || 'admin');
    await page.locator('#password').fill(fs.readFileSync(passwordFile,'utf8').trim());
    await page.locator('button[type=submit]').click();
    await page.waitForURL(url=>!url.pathname.includes('login'));
    await page.goto(base+'/detection-engineering');
    await page.waitForLoadState('networkidle');
    const baselineListeners=await page.evaluate(()=>window.deListenerBalance);
    if ((await page.request.get(base+'/api/de/proposals')).status()!==404) throw new Error('Fixture must run with the separate DE module disabled.');
    if (await page.locator('[data-field="total_rules"]').textContent()!=='2') throw new Error('Posture fixture not rendered.');
    if (await page.locator('#de-space-select option').count()!==2) throw new Error('Spaces did not render.');
    for (const [tab,text] of [['killchains','Use case <safe>'],['rules','Rule "quoted" <safe>'],['execution','Total Alerts'],['readiness','Actor <safe>'],['progression','Host <safe>'],['gaps','Blind Spots'],['d3fend','Defence <safe>'],['emulation','Plan <safe>'],['vulns','Vulnerability <safe>']]) {
      await page.locator('.de-tab[data-tab="'+tab+'"]').click();
      await page.waitForFunction(({tab,text})=>document.getElementById('de-panel-'+tab).textContent.includes(text),{tab,text});
      console.log('Panel passed: '+tab);
    }
    for(const tab of ['d3fend','emulation','vulns']) {
      await page.locator('.de-tab[data-tab="'+tab+'"]').click();
      await page.waitForLoadState('networkidle');
      if(catalogueReads[tab]!==1) throw new Error('Revisiting '+tab+' reloaded a cached panel.');
    }
    await page.locator('.de-tab[data-tab="rules"]').click();
    await page.locator('#de-rules-search').fill('quoted" <safe> &');
    await page.locator('[data-click-action="deRulesSearch"]').click();
    await page.waitForLoadState('networkidle');
    await page.getByRole('button',{name:'Next',exact:true}).click();
    await page.waitForFunction(()=>document.getElementById('de-rules-body').textContent.includes('<safe>50'));
    await page.locator('.de-tab[data-tab="execution"]').click();
    await page.locator('[data-click-action="deExecSetHours"]').first().click();
    await page.waitForFunction(()=>document.getElementById('de-panel-execution').textContent.includes('last 24h'));
    await page.locator('.de-tab[data-tab="progression"]').click();
    await page.locator('[data-click-action="deProgSetHours"]').last().click();
    await page.waitForLoadState('networkidle');
    await page.locator('.de-tab[data-tab="readiness"]').click();
    await page.locator('.de-actor-header').click();
    await page.locator('#de-readiness-system').selectOption('system-1');
    await page.locator('[data-click-action="deGenerateReport"]').click();
    await page.waitForFunction(()=>document.getElementById('de-sysreadiness-actor"quoted').textContent.includes('System <safe>'));
    await page.locator('.de-tab[data-tab="emulation"]').click();
    await page.locator('[data-click-action="emOpenPlan"]').click();
    await page.waitForFunction(()=>document.getElementById('de-emulation-detail').textContent.includes('Add Step'));
    const mutationCalls=[];
    await page.route('**/api/emulation/steps/1/execute',route=>{mutationCalls.push(route.request().method());return route.fulfill({status:200,contentType:'application/json',body:'{}'});});
    await page.locator('[data-click-action="emExecuteStep"]').click();
    await page.waitForLoadState('networkidle');
    if(mutationCalls.join()!=='POST') throw new Error('Execute action did not call the existing API.');
    await page.route('**/api/cyab/tide/de/spaces/*',route=>route.fulfill({status:200,contentType:'application/json',body:'{"ok":true}'}));
    await page.route('**/api/cyab/tide/de/sync-now',route=>route.fulfill({status:200,contentType:'application/json',body:'{"synced":0,"total":0}'}));
    await page.locator('#de-space-select').selectOption('quoted"space');
    await page.waitForLoadState('networkidle');
    await page.locator('[data-click-action="deSyncTide"]').click();
    await page.waitForFunction(()=>document.getElementById('de-tide-badge').textContent.includes('0/0'));
    await page.waitForLoadState('networkidle');
    const invalid=await page.locator('[data-args]').evaluateAll(nodes=>nodes.filter(node=>{try{JSON.parse(node.dataset.args);return false;}catch{return true;}}).map(node=>node.outerHTML));
    if(invalid.length) throw new Error('Invalid action JSON: '+invalid.join('\n'));
    if(await page.locator('safe').count()) throw new Error('Unescaped data became markup.');
    for(const status of [403,500]) {
      const url='/ui/detection-engineering/posture?smoke='+status;
      await page.route('**'+url,route=>route.fulfill({status,contentType:'text/html',body:'Refused'}));
      const success=await page.evaluate(url=>deLoadFragment(url,'de-panel-posture','Loading...'),url);
      const text=await page.locator('#de-panel-posture').textContent();
      if(success || !text.includes(status===403?'permission':'nothing here has been measured')) throw new Error('HTTP '+status+' lost its shared failure explanation: '+text);
      if(await page.evaluate(()=>window.deListenerBalance)!==baselineListeners) throw new Error('Fragment listener leaked.');
    }
    await page.route('**/ui/detection-engineering/posture?race=old',async route=>{
      await new Promise(resolve=>setTimeout(resolve,200));
      await route.fulfill({status:200,contentType:'text/html',body:'<p>Stale response</p>'}).catch(()=>{});
    });
    await page.route('**/ui/detection-engineering/posture?race=new',route=>route.fulfill({status:200,contentType:'text/html',body:'<p>Current response</p>'}));
    await page.evaluate(async()=>{
      const old=deLoadFragment('/ui/detection-engineering/posture?race=old','de-panel-posture');
      const current=deLoadFragment('/ui/detection-engineering/posture?race=new','de-panel-posture');
      await Promise.all([old,current]);
    });
    await page.waitForLoadState('networkidle');
    if((await page.locator('#de-panel-posture').textContent()).trim()!=='Current response') throw new Error('An earlier response overwrote a newer request.');
    if(await page.evaluate(()=>window.deListenerBalance)!==baselineListeners) throw new Error('Cancelled request leaked a listener.');
    if(errors.length) throw new Error(errors.join('\n'));
    fs.mkdirSync('.audit',{recursive:true});
    await page.screenshot({path:'.audit/detection-engineering-dark.png',fullPage:true});
    await page.evaluate(()=>document.documentElement.setAttribute('data-mode','light'));
    await page.waitForTimeout(300);
    await page.screenshot({path:'.audit/detection-engineering-light.png',fullPage:true});
    console.log('Controls, disabled-module access, JSON arguments, quoted identifiers, HTTP failures and listener cleanup passed.');
  } finally {
    await browser.close();
  }
})().catch(error=>{console.error(error);process.exit(1);});
