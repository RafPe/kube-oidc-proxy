(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const {nodes, scenarios} = MAP_DATA;
  const {paths} = FlowModel;
  let scenario = 'oidc', order = paths.oidc, index = 0;
  const escape = text => String(text).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
  $('scenario').innerHTML = Object.entries(scenarios).map(([id,s]) => `<option value="${id}">${escape(s.label)}</option>`).join('');
  function writeHash() {
    const hash = `${scenario}/${order[index]}`;
    if (location.hash.slice(1) !== hash) history.replaceState(null, '', `#${hash}`);
  }
  function renderDetail() {
    const id = order[index], node = nodes[id];
    $('breadcrumb').textContent = `Step ${index + 1} of ${order.length}`;
    $('detail').innerHTML = `<div class="category">${escape(node.tag)}</div><h2>${escape(node.title)}</h2><p class="summary">${escape(node.summary)}</p>
      <div class="io-grid"><div class="io"><b>IN</b><pre>${escape(node.input)}</pre></div><div class="io"><b>OUT</b><pre>${escape(node.output)}</pre></div></div>
      <div class="section-label">WHAT HAPPENS</div><p class="mechanics">${escape(node.detail)}</p>`;
    $('announcement').textContent = `Step ${index+1} of ${order.length}: ${node.title}`;
  }
  function renderFlow() {
    $('flow').innerHTML = order.map((id,i) => `<li class="flow-item">
      <button class="stage ${i === index ? 'selected' : ''}" data-stage="${i}" ${i === index ? 'aria-current="step"' : ''}>
        <span class="step-number">${String(i+1).padStart(2,'0')}</span><span class="stage-title">${escape(nodes[id].title)}</span>
      </button></li>`).join('');
  }
  function render() { renderFlow(); renderDetail(); writeHash(); }
  function changeScenario(id, selected) {
    scenario = Object.hasOwn(paths,id) ? id : 'oidc';
    order = paths[scenario];
    index = Math.max(0, order.indexOf(selected));
    $('scenario').value = scenario;
    $('scenario-note').textContent = scenarios[scenario].note;
    $('result').textContent = scenarios[scenario].result;
    render();
    const item = $('flow').children[index], viewport = item.closest('.flow-scroll');
    viewport.scrollTop = item.offsetTop - $('flow').children[0].offsetTop;
  }
  function fromHash() { const [id, selected] = location.hash.slice(1).split('/'); changeScenario(id, selected); }
  $('scenario').addEventListener('change', e => changeScenario(e.target.value));
  $('flow').addEventListener('click', e => {
    const stage = e.target.closest('[data-stage]');
    if (!stage) return;
    index = Number(stage.dataset.stage);
    render();
    $('flow').querySelector(`[data-stage="${index}"]`).focus({preventScroll:true});
  });
  $('copy-link').addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(location.href); $('copy-link').textContent = 'Copied'; }
    catch { $('copy-link').textContent = 'Use address bar'; $('announcement').textContent = 'Copy the current URL from your address bar to link to this step.'; }
    setTimeout(() => { $('copy-link').textContent = 'Copy link'; }, 2500);
  });
  window.addEventListener('hashchange', fromHash);
  fromHash();
})();
