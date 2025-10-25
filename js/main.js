// js/main.js — Leyaps (Cognito PKCE + UI)

const html = document.documentElement;

/* =======================
   Tema y tamaño de fuente
   ======================= */
const savedScale = localStorage.getItem('leyaps_scale');
if (savedScale) html.style.setProperty('--scale', savedScale);

const applyTheme = (val) => {
  if (val === 'auto') html.removeAttribute('data-theme');
  else html.setAttribute('data-theme', val);
  localStorage.setItem('leyaps_theme', val);
  document.querySelector('#contrast')?.setAttribute('aria-pressed', String(val === 'contrast'));
  const picker = document.querySelector('#theme'); if (picker) picker.value = val;
};
applyTheme(localStorage.getItem('leyaps_theme') || 'contrast');

/* =======================
   Helpers de rutas/plantillas
   ======================= */
const parts = location.pathname.split('/').filter(Boolean);
const prefix = '../'.repeat(Math.max(0, parts.length - 1));

async function inject(id, path){
  const el = document.getElementById(id);
  if (!el) return;
  const res = await fetch(prefix + path);
  el.innerHTML = await res.text();
  if (path.includes('header')) initHeader();
}

function initHeader(){
  // Tema y contraste
  const themePicker = document.querySelector('#theme');
  const contrastBtn = document.querySelector('#contrast');
  themePicker?.addEventListener('change', e => applyTheme(e.target.value));
  let lastNonContrast = (localStorage.getItem('leyaps_theme') || 'light') === 'contrast'
    ? 'light'
    : (localStorage.getItem('leyaps_theme') || 'light');
  contrastBtn?.addEventListener('click', () => {
    const now = localStorage.getItem('leyaps_theme') || 'auto';
    if (now === 'contrast') applyTheme(lastNonContrast);
    else { lastNonContrast = now; applyTheme('contrast'); }
  });

  // Tamaño de fuente
  const clamp = (n,min,max)=> Math.min(Math.max(n,min),max);
  const getScale = ()=> parseFloat(getComputedStyle(html).getPropertyValue('--scale')) || 1;
  const setScale = (v)=>{ html.style.setProperty('--scale', String(v)); localStorage.setItem('leyaps_scale', String(v)); };
  document.querySelector('#fontMinus')?.addEventListener('click', ()=> setScale(clamp(getScale()-0.1,0.9,1.4)));
  document.querySelector('#fontPlus')?.addEventListener('click', ()=> setScale(clamp(getScale()+0.1,0.9,1.4)));

  // Drawer móvil
  const openMenu = document.querySelector('#openMenu');
  const closeMenu = document.querySelector('#closeMenu');
  const drawer = document.querySelector('#drawer');
  const toggle = (open)=>{ drawer?.classList.toggle('drawer--open', open); drawer?.setAttribute('aria-hidden', String(!open)); openMenu?.setAttribute('aria-expanded', String(open)); };
  openMenu?.addEventListener('click', ()=> toggle(true));
  closeMenu?.addEventListener('click', ()=> toggle(false));
  window.addEventListener('keydown', e=>{ if(e.key==='Escape') toggle(false); });

  // Link activo
  document.querySelectorAll('.nav__link').forEach(a=>{
    const url = new URL(a.href, location.origin);
    if (url.pathname === location.pathname) a.setAttribute('aria-current','page');
  });

  // Botones auth
  document.getElementById('loginBtn')?.addEventListener('click', e=>{ e.preventDefault(); login(); });
  document.getElementById('logoutBtn')?.addEventListener('click', e=>{ e.preventDefault(); logout(); });
  document.getElementById('drawerLogin')?.addEventListener('click', e=>{ e.preventDefault(); toggle(false); login(); });
  document.getElementById('drawerLogout')?.addEventListener('click', e=>{ e.preventDefault(); toggle(false); logout(); });
}

/* =======================
   Auth con Cognito (PKCE)
   ======================= */
const COGNITO = {
  region: 'sa-east-1',
  userPoolId: 'sa-east-1_1qy1cryrN',
  clientId: '336rirqphirf74mn0pjv5dmqqq',
  domain: 'sa-east-11qy1cryrn' // prefijo del Hosted UI
};
const baseHost = () => `https://${COGNITO.domain}.auth.${COGNITO.region}.amazoncognito.com`;
const redirectUri = () => `${location.origin}/`;
const logoutRedirectUri = () => `${location.origin}/`;

const b64url = (buf) =>
  btoa(String.fromCharCode.apply(null, new Uint8Array(buf)))
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const randomString = (len=64) => {
  const chars='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  const rnd=new Uint32Array(len); crypto.getRandomValues(rnd);
  return Array.from(rnd,n=>chars[n%chars.length]).join('');
};
async function sha256b64(text){
  const data=new TextEncoder().encode(text);
  const hash=await crypto.subtle.digest('SHA-256', data);
  return b64url(hash);
}

// >>> Cambiado a /login para Managed Sign-in Pages <<<
async function login(){
  const verifier = randomString(64);
  const challenge = await sha256b64(verifier);
  sessionStorage.setItem('pkce_verifier', verifier);
  sessionStorage.setItem('redirect_uri', redirectUri());

  const url = new URL(baseHost() + '/oauth2/authorize');
  url.search = new URLSearchParams({
    client_id: COGNITO.clientId,
    response_type: 'code',
    scope: 'openid email profile',
    redirect_uri: redirectUri(),
    code_challenge_method: 'S256',
    code_challenge: challenge
  }).toString();

  location.assign(url.toString());
}

function parseJwt(token){
  try{
    const payload = token.split('.')[1];
    return JSON.parse(atob(payload.replace(/-/g,'+').replace(/_/g,'/')));
  }catch(_){ return null; }
}
function isLoggedIn(){ return !!localStorage.getItem('leyaps_id_token'); }
function updateAuthUI(){
  const lb=document.getElementById('loginBtn'),
        lo=document.getElementById('logoutBtn'),
        dlb=document.getElementById('drawerLogin'),
        dlo=document.getElementById('drawerLogout');
  if(isLoggedIn()){
    const p=parseJwt(localStorage.getItem('leyaps_id_token'))||{};
    if(lb) lb.textContent = p.email ? p.email.split('@')[0] : 'Mi cuenta';
    lo?.setAttribute('style','display:inline-block');
    dlb?.setAttribute('style','display:none');
    dlo?.setAttribute('style','display:inline-block');
  }else{
    if(lb) lb.textContent='Entrar';
    lo?.setAttribute('style','display:none');
    dlb?.setAttribute('style','display:inline-block');
    dlo?.setAttribute('style','display:none');
  }
}

async function handleOAuthCallback(){
  const code = new URLSearchParams(location.search).get('code');
  if(!code) return;

  const verifier = sessionStorage.getItem('pkce_verifier');
  const redir = sessionStorage.getItem('redirect_uri') || redirectUri();

  const body = new URLSearchParams({
    grant_type:'authorization_code',
    client_id:COGNITO.clientId,
    code_verifier:verifier,
    code,
    redirect_uri:redir
  });

  const res = await fetch(baseHost() + '/oauth2/token', {
    method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body
  });
  const data = await res.json();

  if(data.id_token){
    localStorage.setItem('leyaps_id_token', data.id_token);
    localStorage.setItem('leyaps_access_token', data.access_token);
    if(data.refresh_token) localStorage.setItem('leyaps_refresh_token', data.refresh_token);
    history.replaceState({}, '', location.pathname);
  }else{
    console.warn('Error de token', data);
    alert('No se pudo iniciar sesión.');
  }
}

function logout(){
  const out = logoutRedirectUri();
  localStorage.removeItem('leyaps_id_token');
  localStorage.removeItem('leyaps_access_token');
  localStorage.removeItem('leyaps_refresh_token');
  updateAuthUI();

  const url = new URL(baseHost() + '/logout');
  url.search = new URLSearchParams({
    client_id: COGNITO.clientId,
    logout_uri: out
  }).toString();
  location.assign(url.toString());
}

/* =======================
   Boot: plantillas + búsqueda + auth
   ======================= */
async function boot(){
  await inject('app-header','components/header.html');
  await inject('app-footer','components/footer.html');

  // Búsqueda demo
  const q=document.getElementById('q'),
        go=document.getElementById('doSearch');
  go?.addEventListener('click', ()=>{
    if(!q.value.trim()) return q.focus();
    location.href='buscar.html?q='+encodeURIComponent(q.value.trim());
  });
  document.querySelectorAll('[data-chip]').forEach(b=>{
    b.addEventListener('click', ()=>{
      if(q){ q.value=b.dataset.chip; q.focus(); }
      else { location.href='buscar.html?q='+encodeURIComponent(b.dataset.chip); }
    });
  });

  await handleOAuthCallback();
  updateAuthUI();
}
boot();
