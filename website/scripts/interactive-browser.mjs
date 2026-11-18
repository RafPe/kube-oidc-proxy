import puppeteer from 'puppeteer-core';
import assert from 'node:assert/strict';
import content from '../src/components/interactive/request-content.cjs';
import model from '../src/components/interactive/request-model.cjs';

const base = process.env.PREVIEW_URL || 'http://127.0.0.1:4321/kube-oidc-proxy';
const browser = await puppeteer.launch({executablePath:process.env.CHROME_PATH,headless:true});
try {
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror',error=>errors.push(error.message));
  await page.setViewport({width:1440,height:1100});
  await page.goto(`${base}/interactive/request-flow/`);
  await page.waitForSelector('.stage');
  const title = () => page.$eval('#detail h2',el=>el.textContent);
  assert.equal(await title(),content.nodes.client.title);
  for (const [scenario,path] of Object.entries(model.paths)) {
    await page.select('#scenario',scenario);
    assert.equal(await page.$$eval('.stage',els=>els.length),path.length);
    for(let i=0;i<path.length;i++) {
      await page.$eval(`[data-stage="${i}"]`,el=>el.click());
      assert.equal(await title(),content.nodes[path[i]].title);
      assert.equal(await page.$('#detail .source'),null);
      assert(await page.$eval('#detail .mechanics',el=>el.textContent.length>0));
    }
  }
  assert.equal(await page.$('#play, #sandbox, #position, [draggable="true"]'),null);
  await page.select('#scenario','oidc');
  await page.focus('[data-stage="1"]');
  await page.keyboard.press('Enter');
  assert.equal(await title(),content.nodes.requestid.title);
  await page.goto(`${base}/interactive/request-flow/#passthrough/review`);
  await page.waitForSelector('#detail h2');
  assert.equal(await title(),content.nodes.review.title);
  await page.reload();
  await page.waitForSelector('#detail h2');
  assert.equal(await title(),content.nodes.review.title);
  await page.select('#scenario','oidc');
  await page.$eval('[data-stage="5"]',el=>el.click());
  for(const theme of ['light','dark']) {
    await page.evaluate(t=>{document.documentElement.dataset.theme=t;localStorage.setItem('starlight-theme',t);},theme);
    await page.evaluate(()=>window.scrollTo(0,0));
    await page.evaluate(()=>Promise.all(document.getAnimations().map(animation=>animation.finished.catch(()=>{}))));
    await page.screenshot({path:`/tmp/request-docs-${theme}.png`,fullPage:true});
  }
  for(const size of [{width:390,height:844},{width:844,height:390},{width:768,height:1024}]) {
    await page.setViewport(size);
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`Flow overflow at ${size.width}`);
  }
  await page.setViewport({width:1440,height:1100});
  await page.goto(`${base}/interactive/identity-and-rbac/`);
  await page.waitForFunction(()=>document.querySelector('#identity-verdict')?.textContent.includes('Allowed by'));
  assert.equal(await page.$eval('#identity-options',el=>el.open),false);
  assert.equal(await page.$eval('#identity-details',el=>el.open),false);
  const verdict=()=>page.$eval('.identity-outcome',el=>el.textContent);
  const fill=async(name,value)=>page.$eval(`[name="${name}"]`,(el,v)=>{el.value=v;el.dispatchEvent(new Event('input',{bubbles:true}));},value);
  assert.equal(await page.$eval('#identity-name',el=>el.textContent),'oidc-a:alice@example.com');
  assert(await page.$eval('#identity-yaml',el=>el.checkVisibility()));
  assert(await page.$('#identity-yaml .yaml-key'));
  assert.match(await page.$eval('#identity-role-yaml',el=>el.textContent),/resources: \["pods"\]/);
  const roleYaml = await page.$eval('#identity-role-yaml',el=>el.textContent);
  await page.click('[data-resource="secrets"]'); assert.match(await verdict(),/not granted/);
  assert.equal(await page.$eval('#identity-role-yaml',el=>el.textContent),roleYaml);
  await page.select('[name="example"]','bob'); assert.match(await verdict(),/Allowed by/);
  assert.equal(await page.$eval('#identity-name',el=>el.textContent),'oidc-b:bob@example.com');
  await page.click('#identity-options > summary');
  await page.select('[name="bindingScope"]','namespace'); assert.match(await verdict(),/not granted/);
  assert.match(await page.$eval('#identity-yaml',el=>el.textContent),/kind: RoleBinding/);
  assert.match(await page.$eval('#identity-yaml',el=>el.textContent),/namespace: development/);
  await page.select('[name="namespace"]','development'); assert.match(await verdict(),/Allowed by/);
  await page.select('[name="namespace"]','production'); assert.match(await verdict(),/not granted/);
  await page.select('[name="example"]','github'); assert.match(await verdict(),/Allowed by/);
  await page.select('[name="kind"]','User'); assert.match(await verdict(),/not granted/);
  await page.click('#identity-reset'); assert.match(await verdict(),/Allowed by/);
  await page.select('[name="example"]','impersonation');
  assert.equal(await page.$eval('#identity-name',el=>el.textContent),'ci-viewer');
  await page.click('[name="callerGrant"]'); assert.match(await verdict(),/Stopped at proxy/);
  assert.equal(await page.$eval('#identity-name',el=>el.textContent),'No upstream request');
  await page.click('[name="callerGrant"]');
  await page.click('[name="proxyGrant"]'); assert.match(await verdict(),/Rejected upstream/);
  await page.click('#identity-reset');
  await fill('subject','<img src=x onerror=alert(1)>');
  assert.equal(await page.$('#identity-checks img'),null);
  assert.equal(await page.$('#identity-yaml img'),null);
  assert.match(await page.$eval('#identity-yaml',el=>el.textContent),/<img src=x onerror=alert\(1\)>/);
  await page.click('#identity-reset');
  await page.evaluate(()=>{document.documentElement.dataset.theme='light';window.scrollTo(0,0);});
  await page.waitForFunction(()=>getComputedStyle(document.querySelector('#identity-reset')).backgroundColor===getComputedStyle(document.querySelector('.identity-results')).backgroundColor);
  await page.$eval('#identity-options',el=>{el.open=false;});
  await page.screenshot({path:'/tmp/request-docs-identity.png',fullPage:true});
  await page.setViewport({width:390,height:844});
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'Identity overflow');
  await page.screenshot({path:'/tmp/request-docs-mobile.png',fullPage:true});
  assert.deepEqual(errors,[]);
  console.log('Interactive browser checks passed: scenarios, explanations, step selection, deep links, identity rules, text escaping, and responsive layouts.');
} finally { await browser.close(); }
