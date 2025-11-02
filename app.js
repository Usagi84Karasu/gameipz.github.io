// app.js (frontend)
const api = {
  request: async (path, opts = {}) => {
    const token = localStorage.getItem('token');
    opts.headers = opts.headers || {};
    if (token) opts.headers['Authorization'] = 'Bearer ' + token;
    if (!opts.headers['Content-Type'] && opts.body) opts.headers['Content-Type'] = 'application/json';
    const res = await fetch(path, opts);
    const text = await res.text();
    try { return { ok: res.ok, data: JSON.parse(text) }; } catch(e) { return { ok: res.ok, data: text }; }
  }
};

function $(sel){ return document.querySelector(sel) }
function $all(sel){ return Array.from(document.querySelectorAll(sel)) }

async function init(){
  bindAuth();
  await loadGames();
}

function bindAuth(){
  const token = localStorage.getItem('token');
  if (token) showUser();
  else showLogin();

  $('#loginBtn').onclick = async () => {
    const username = $('#login-username').value.trim();
    const password = $('#login-password').value;
    if (!username || !password) return alert('remplis username & password');
    const r = await api.request('/api/login', { method:'POST', body: JSON.stringify({ username, password }) });
    if (r.ok) {
      localStorage.setItem('token', r.data.token);
      localStorage.setItem('username', r.data.username);
      showUser();
      await loadGames();
    } else alert(r.data.error || 'error');
  };

  $('#registerBtn').onclick = async () => {
    const username = $('#login-username').value.trim();
    const password = $('#login-password').value;
    if (!username || !password) return alert('remplis username & password');
    const r = await api.request('/api/register', { method:'POST', body: JSON.stringify({ username, password }) });
    if (r.ok) {
      localStorage.setItem('token', r.data.token);
      localStorage.setItem('username', r.data.username);
      showUser();
      await loadGames();
    } else alert(r.data.error || 'error');
  };

  $('#logoutBtn').onclick = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    showLogin();
    loadGames();
  };

  $('#createGameBtn').onclick = async () => {
    const title = $('#game-title').value.trim();
    const description = $('#game-desc').value.trim();
    const html = $('#game-html').value;
    if (!title || !html) return alert('Titre + HTML requis');
    const r = await api.request('/api/games', { method:'POST', body: JSON.stringify({ title, description, html }) });
    if (r.ok) {
      alert('Jeu créé — tu peux le publier depuis la liste.');
      $('#game-title').value=''; $('#game-desc').value=''; $('#game-html').value='';
      await loadGames();
    } else alert(r.data.error || 'Erreur création');
  };
}

function showUser(){
  $('#login-area').classList.add('hidden');
  $('#user-info').classList.remove('hidden');
  $('#username').innerText = localStorage.getItem('username') || 'User';
}
function showLogin(){
  $('#login-area').classList.remove('hidden');
  $('#user-info').classList.add('hidden');
  $('#username').innerText = '';
}

async function loadGames(){
  $('#gamesList').innerText = 'Chargement…';
  const r = await api.request('/api/games');
  if (!r.ok) { $('#gamesList').innerText = 'Erreur chargement'; return;}
  const rows = r.data;
  if (!rows.length) { $('#gamesList').innerText = 'Aucun jeu trouvé'; return; }
  const container = document.createElement('div');
  rows.forEach(g => {
    const el = document.createElement('div');
    el.className = 'game';
    el.innerHTML = `<div>
      <strong>${escapeHtml(g.title)}</strong>
      <div style="font-size:.9rem;color:#666">${escapeHtml(g.description || '')}</div>
      <div style="font-size:.8rem;color:#888">par ${escapeHtml(g.owner_name)} • ${g.published ? 'Publié' : 'Privé'}</div>
    </div>`;
    const actions = document.createElement('div');
    const previewBtn = document.createElement('button');
    previewBtn.innerText = 'Prévisualiser';
    previewBtn.onclick = () => previewGame(g.id);
    actions.appendChild(previewBtn);

    // if current user is owner, show publish toggle
    const username = localStorage.getItem('username');
    if (username && username === g.owner_name) {
      const pubBtn = document.createElement('button');
      pubBtn.className = 'smallbtn';
      pubBtn.innerText = g.published ? 'Dépublier' : 'Publier';
      pubBtn.onclick = async () => {
        const token = localStorage.getItem('token');
        if (!token) return alert('Connecte-toi');
        const rr = await fetch(`/api/games/${g.id}/publish`, {
          method:'POST',
          headers: { 'Content-Type':'application/json', 'Authorization':'Bearer '+token },
          body: JSON.stringify({ publish: !g.published })
        });
        const data = await rr.json();
        if (rr.ok) { alert('Mise à jour'); await loadGames(); } else alert(data.error || 'error');
      };
      actions.appendChild(pubBtn);
    }

    el.appendChild(actions);
    container.appendChild(el);
  });
  const list = $('#gamesList');
  list.innerHTML = '';
  list.appendChild(container);
}

async function previewGame(id){
  const meta = await api.request('/api/games/' + id);
  if (!meta.ok) {
    // maybe not published, try to fetch anyway (the /play route will refuse if not published)
    // but we attempt to open /play/:id in iframe to show published games.
  }
  const previewArea = $('#previewArea');
  previewArea.innerHTML = '';
  const iframe = document.createElement('iframe');
  // sandbox to restrict capabilities; allow-scripts for games that need JS
  iframe.setAttribute('sandbox', 'allow-scripts allow-forms allow-pointer-lock');
  iframe.src = `/play/${id}`;
  previewArea.appendChild(iframe);
}

function escapeHtml(s){ return String(s||'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])) }

init();
                                      
