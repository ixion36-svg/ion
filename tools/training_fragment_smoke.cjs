/* Run against a local ION server with a dedicated test account.
 * ION_SMOKE_PASSWORD_FILE (or argv[2]) supplies its password without logging it.
 * Optional: ION_SMOKE_BASE_URL, ION_SMOKE_USERNAME, PLAYWRIGHT_NODE_MODULES,
 * PLAYWRIGHT_CHROMIUM_EXECUTABLE.
 */
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require(process.env.PLAYWRIGHT_NODE_MODULES
  ? path.join(process.env.PLAYWRIGHT_NODE_MODULES, 'playwright') : 'playwright');

(async () => {
  const base = process.env.ION_SMOKE_BASE_URL || 'http://127.0.0.1:8819';
  const passwordFile = process.env.ION_SMOKE_PASSWORD_FILE || process.argv[2];
  if (!passwordFile) throw new Error('Set ION_SMOKE_PASSWORD_FILE or pass the password file as argv[2].');
  const options = {headless: true};
  if (process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE) options.executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE;
  const browser = await chromium.launch(options);
  try {
    const page = await browser.newPage();
    await page.goto(base + '/login');
    await page.locator('#username').fill(process.env.ION_SMOKE_USERNAME || 'admin');
    await page.locator('#password').fill(fs.readFileSync(passwordFile, 'utf8').trim());
    await page.locator('button[type=submit]').click();
    await page.waitForURL(url => !url.pathname.includes('login'));
    await page.goto(base + '/training');
    await page.waitForLoadState('networkidle');
    let failures = 0;
    for (const status of [200, 403, 500]) {
      const url = '/ui/training/forecast?regression=' + status;
      await page.route('**' + url, route => route.fulfill({status, contentType: 'text/html', body: '<p>Regression data.</p>'}));
      const result = await page.evaluate(async ({url, status}) => {
        const add = document.addEventListener;
        const remove = document.removeEventListener;
        let listeners = 0;
        document.addEventListener = function(type, ...args) {
          if (type === 'htmx:afterRequest') listeners++;
          return add.call(this, type, ...args);
        };
        document.removeEventListener = function(type, ...args) {
          if (type === 'htmx:afterRequest') listeners--;
          return remove.call(this, type, ...args);
        };
        try {
          await tpLoadFragment(url, 'tp-forecast-content', 'Regression read failed.');
          const text = document.getElementById('tp-forecast-content').textContent;
          return {status, text, listeners, pass: text === (status === 200 ? 'Regression data.' : 'Regression read failed.') && listeners === 0};
        } finally {
          document.addEventListener = add;
          document.removeEventListener = remove;
        }
      }, {url, status});
      console.log(JSON.stringify(result));
      if (!result.pass) failures++;
    }
    if (failures) process.exitCode = 1;
  } finally { await browser.close(); }
})().catch(error => {console.error(error.message); process.exitCode = 1;});
