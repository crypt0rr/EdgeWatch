// Business-units prototype: the floating persona switcher. The mock API
// plugin injects it into index.html only while `vite --mode prototype` serves
// the console; it is plain inline HTML and never part of the app bundle.

type Persona = { key: string; label: string; hint: string }

const STYLE = String.raw`
#proto-persona { position: fixed; right: 16px; bottom: 16px; z-index: 2147483000; width: min(330px, calc(100vw - 32px)); font: 12px/1.45 Inter, ui-sans-serif, system-ui, sans-serif; color: #f3e9ff; }
#proto-persona .pp-card { border: 1px solid #8f6bd8; border-radius: 12px; background: #1d1433f2; box-shadow: 0 12px 40px #0009; overflow: hidden; }
#proto-persona .pp-head { display: flex; align-items: center; gap: 8px; width: 100%; padding: 9px 12px; border: 0; background: #2c1e4d; color: inherit; font: inherit; font-weight: 700; text-align: left; cursor: pointer; }
#proto-persona .pp-head span { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
#proto-persona .pp-tag { flex: 0 0 auto; padding: 2px 7px; border-radius: 99px; background: #8f6bd8; color: #fff; font-size: 10px; letter-spacing: .06em; text-transform: uppercase; }
#proto-persona .pp-body { display: grid; gap: 8px; padding: 12px; }
#proto-persona label { display: grid; gap: 5px; color: #d9c8ff; font-weight: 600; }
#proto-persona select { width: 100%; min-height: 36px; padding: 7px 9px; border: 1px solid #6e52a8; border-radius: 7px; background: #120c22; color: #fff; font: inherit; }
#proto-persona .pp-hint { margin: 0; color: #e8dcff; }
#proto-persona .pp-foot { display: flex; align-items: center; justify-content: space-between; gap: 8px; color: #b9a6e0; font-size: 11px; }
#proto-persona .pp-foot button { padding: 5px 9px; border: 1px solid #6e52a8; border-radius: 6px; background: transparent; color: #e8dcff; font: inherit; cursor: pointer; }
#proto-persona.pp-collapsed { width: auto; max-width: min(330px, calc(100vw - 32px)); }
#proto-persona.pp-collapsed .pp-body { display: none; }
@media (max-width: 760px) { #proto-persona { right: 10px; bottom: 10px; } }
`

const SCRIPT = String.raw`
(function () {
  var personas = __PERSONAS__;
  var fallback = __DEFAULT__;
  var cookieName = 'proto_persona';
  function current() {
    var parts = document.cookie ? document.cookie.split('; ') : [];
    for (var i = 0; i < parts.length; i++) {
      if (parts[i].indexOf(cookieName + '=') === 0) return decodeURIComponent(parts[i].slice(cookieName.length + 1));
    }
    return fallback;
  }
  function find(key) {
    for (var i = 0; i < personas.length; i++) if (personas[i].key === key) return personas[i];
    return null;
  }
  var root = document.createElement('aside');
  root.id = 'proto-persona';
  root.setAttribute('aria-label', 'Prototype persona switcher');
  var card = document.createElement('div');
  card.className = 'pp-card';
  var head = document.createElement('button');
  head.type = 'button';
  head.className = 'pp-head';
  var tag = document.createElement('b');
  tag.className = 'pp-tag';
  tag.textContent = 'Prototype';
  var title = document.createElement('span');
  head.appendChild(tag);
  head.appendChild(title);
  var body = document.createElement('div');
  body.className = 'pp-body';
  body.id = 'proto-persona-body';
  head.setAttribute('aria-controls', body.id);
  var label = document.createElement('label');
  label.textContent = 'Viewing as';
  var select = document.createElement('select');
  for (var i = 0; i < personas.length; i++) {
    var option = document.createElement('option');
    option.value = personas[i].key;
    option.textContent = personas[i].label;
    select.appendChild(option);
  }
  var other = document.createElement('option');
  other.value = '';
  other.textContent = 'Another account (signed in)';
  other.disabled = true;
  select.appendChild(other);
  label.appendChild(select);
  var hint = document.createElement('p');
  hint.className = 'pp-hint';
  var foot = document.createElement('div');
  foot.className = 'pp-foot';
  var note = document.createElement('span');
  note.textContent = 'Mock data · resets on dev server restart';
  var reset = document.createElement('button');
  reset.type = 'button';
  reset.textContent = 'Reset data';
  foot.appendChild(note);
  foot.appendChild(reset);
  body.appendChild(label);
  body.appendChild(hint);
  body.appendChild(foot);
  card.appendChild(head);
  card.appendChild(body);
  root.appendChild(card);
  // Start collapsed on every page load so the switcher never covers the
  // console's own buttons; it expands only while someone is using it.
  var collapsed = true;
  function render() {
    var key = current();
    var persona = find(key);
    select.value = persona ? key : '';
    title.textContent = 'Viewing as: ' + (persona ? persona.label : 'another account');
    hint.textContent = persona ? persona.hint : 'Signed in through the login form. Pick a persona to switch.';
    root.className = collapsed ? 'pp-collapsed' : '';
    head.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
  }
  head.addEventListener('click', function () {
    collapsed = !collapsed;
    render();
    if (!collapsed) select.focus();
  });
  root.addEventListener('keydown', function (event) {
    if (event.key === 'Escape' && !collapsed) { collapsed = true; render(); head.focus(); }
  });
  select.addEventListener('change', function () {
    var key = select.value;
    if (!key) return;
    document.cookie = cookieName + '=' + encodeURIComponent(key) + '; path=/; SameSite=Lax; max-age=31536000';
    if (key === 'fresh-upgrade') window.location.assign('/setup');
    else if (key === 'signed-out') window.location.assign('/login');
    else window.location.reload();
  });
  reset.addEventListener('click', function () {
    fetch('/__prototype/reset', { method: 'POST' }).then(function () { window.location.reload(); });
  });
  // Signing in or out through the console changes the cookie without a
  // reload; follow it so the switcher always names the active persona.
  var shown = current();
  render();
  window.setInterval(function () {
    var key = current();
    if (key !== shown) { shown = key; render(); }
  }, 1000);
  document.body.appendChild(root);
})();
`

export function personaSwitcherTags(personas: Persona[], defaultPersona: string) {
  const script = SCRIPT.replace('__PERSONAS__', JSON.stringify(personas.map(({ key, label, hint }) => ({ key, label, hint })))).replace('__DEFAULT__', JSON.stringify(defaultPersona))
  return [
    { tag: 'style', attrs: { id: 'proto-persona-style' }, children: STYLE, injectTo: 'head' as const },
    { tag: 'script', attrs: { id: 'proto-persona-script' }, children: script, injectTo: 'body' as const },
  ]
}
