// js/main.js — Leyaps (Cognito PKCE + UI + security by design)

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

  document.querySelector('#contrast')
    ?.setAttribute('aria-pressed', String(val === 'contrast'));

  const picker = document.querySelector('#theme');
  if (picker) picker.value = val;
};

applyTheme(localStorage.getItem('leyaps_theme') || 'contrast');

/* =======================
   Helpers de rutas/plantillas
   ======================= */
const parts = location.pathname.split('/').filter(Boolean);
const prefix = '../'.repeat(Math.max(0, parts.length - 1));

async function inject(id, path) {
  const el = document.getElementById(id);
  if (!el) return;
  const res = await fetch(prefix + path);
  el.innerHTML = await res.text();
  if (path.includes('header')) initHeader();
}

function initHeader() {
  // Tema y contraste
  const themePicker = document.querySelector('#theme');
  const contrastBtn = document.querySelector('#contrast');

  themePicker?.addEventListener('change', e => applyTheme(e.target.value));

  let lastNonContrast =
    (localStorage.getItem('leyaps_theme') || 'light') === 'contrast'
      ? 'light'
      : (localStorage.getItem('leyaps_theme') || 'light');

  contrastBtn?.addEventListener('click', () => {
    const now = localStorage.getItem('leyaps_theme') || 'auto';
    if (now === 'contrast') applyTheme(lastNonContrast);
    else {
      lastNonContrast = now;
      applyTheme('contrast');
    }
  });

  // Tamaño de fuente
  const clamp = (n, min, max) => Math.min(Math.max(n, min), max);
  const getScale = () =>
    parseFloat(getComputedStyle(html).getPropertyValue('--scale')) || 1;
  const setScale = (v) => {
    html.style.setProperty('--scale', String(v));
    localStorage.setItem('leyaps_scale', String(v));
  };

  document.querySelector('#fontMinus')
    ?.addEventListener('click', () => setScale(clamp(getScale() - 0.1, 0.9, 1.4)));
  document.querySelector('#fontPlus')
    ?.addEventListener('click', () => setScale(clamp(getScale() + 0.1, 0.9, 1.4)));

  // Drawer móvil
  const openMenu = document.querySelector('#openMenu');
  const closeMenu = document.querySelector('#closeMenu');
  const drawer = document.querySelector('#drawer');

  const toggle = (open) => {
    drawer?.classList.toggle('drawer--open', open);
    drawer?.setAttribute('aria-hidden', String(!open));
    openMenu?.setAttribute('aria-expanded', String(open));
  };

  openMenu?.addEventListener('click', () => toggle(true));
  closeMenu?.addEventListener('click', () => toggle(false));
  window.addEventListener('keydown', e => {
    if (e.key === 'Escape') toggle(false);
  });

  // Link activo
  document.querySelectorAll('.nav__link').forEach(a => {
    const url = new URL(a.href, location.origin);
    if (url.pathname === location.pathname) {
      a.setAttribute('aria-current', 'page');
    }
  });

  // Botones auth
  document.getElementById('loginBtn')
    ?.addEventListener('click', e => { e.preventDefault(); login(); });
  document.getElementById('logoutBtn')
    ?.addEventListener('click', e => { e.preventDefault(); logout(); });
  document.getElementById('drawerLogin')
    ?.addEventListener('click', e => { e.preventDefault(); toggle(false); login(); });
  document.getElementById('drawerLogout')
    ?.addEventListener('click', e => { e.preventDefault(); toggle(false); logout(); });
}

/* =======================
   Auth con Cognito (PKCE)
   ======================= */

// Config según tu consola de Cognito
const COGNITO = {
  region: 'sa-east-1',
  userPoolId: 'sa-east-1_Cb7yCQ0Oi',
  clientId: 'ea755st9nj7b158fcsecrhflg',
  // Dominio correcto según Cognito
  domain: 'sa-east-1cb7ycqooi'
};

const baseHost = () =>
  `https://${COGNITO.domain}.auth.${COGNITO.region}.amazoncognito.com`;

// Origin fijo a Netlify
const redirectUri = () => 'https://leyaps.netlify.app/';
const logoutRedirectUri = () => 'https://leyaps.netlify.app/';

// ===== Utilidades segura PKCE / URL =====
const b64url = (buf) =>
  btoa(String.fromCharCode.apply(null, new Uint8Array(buf)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/,'');

const randomString = (len = 64) => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  const rnd = new Uint32Array(len);
  crypto.getRandomValues(rnd);
  return Array.from(rnd, n => chars[n % chars.length]).join('');
};

async function sha256b64(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return b64url(hash);
}

function getAuthorizationCodeFromUrl() {
  try {
    const url = new URL(window.location.href);
    return url.searchParams.get('code');
  } catch (error) {
    console.error('Error leyendo authorization code de la URL:', error);
    return null;
  }
}

function removeCodeFromUrl() {
  try {
    const url = new URL(window.location.href);
    url.searchParams.delete('code');
    window.history.replaceState({}, document.title, url.toString());
  } catch (error) {
    console.error('Error limpiando el code de la URL:', error);
  }
}

// ===== Flujo de login (PKCE) =====
async function login() {
  const verifier = randomString(64);
  const challenge = await sha256b64(verifier);

  sessionStorage.setItem('pkce_verifier', verifier);
  sessionStorage.setItem('redirect_uri', redirectUri());

  const url = new URL(baseHost() + '/oauth2/authorize');
  url.search = new URLSearchParams({
    client_id: COGNITO.clientId,
    response_type: 'code',
    scope: 'openid email phone', // principle of least privilege
    redirect_uri: redirectUri(),
    code_challenge_method: 'S256',
    code_challenge: challenge
  }).toString();

  location.assign(url.toString());
}

// ===== Manejo de tokens =====
function parseJwt(token) {
  try {
    const payload = token.split('.')[1];
    return JSON.parse(
      atob(payload.replace(/-/g, '+').replace(/_/g, '/'))
    );
  } catch (_) {
    return null;
  }
}

function getIdToken() {
  return sessionStorage.getItem('leyaps_id_token');
}

function isLoggedIn() {
  return !!getIdToken();
}

function updateAuthUI() {
  const lb  = document.getElementById('loginBtn');
  const lo  = document.getElementById('logoutBtn');
  const dlb = document.getElementById('drawerLogin');
  const dlo = document.getElementById('drawerLogout');

  if (isLoggedIn()) {
    const p = parseJwt(getIdToken()) || {};
    if (lb) lb.textContent = p.email ? p.email.split('@')[0] : 'Mi cuenta';
    lo?.setAttribute('style', 'display:inline-block');
    dlb?.setAttribute('style', 'display:none');
    dlo?.setAttribute('style', 'display:inline-block');
  } else {
    if (lb) lb.textContent = 'Entrar';
    lo?.setAttribute('style', 'display:none');
    dlb?.setAttribute('style', 'display:inline-block');
    dlo?.setAttribute('style', 'display:none');
  }
}

// Intercambio authorization code → tokens (PKCE)
async function handleOAuthCallback() {
  const code = getAuthorizationCodeFromUrl();
  if (!code) return;

  const verifier = sessionStorage.getItem('pkce_verifier');
  const redir = sessionStorage.getItem('redirect_uri') || redirectUri();

  if (!verifier) {
    console.warn('No hay PKCE verifier en sesión. Se aborta intercambio.');
    removeCodeFromUrl();
    return;
  }

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: COGNITO.clientId,
    code_verifier: verifier,
    code,
    redirect_uri: redir
  });

  try {
    const res = await fetch(baseHost() + '/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body
    });

    if (!res.ok) {
      console.warn('Fallo al obtener tokens. HTTP:', res.status);
      removeCodeFromUrl();
      return;
    }

    const data = await res.json();

    if (data.id_token && data.access_token) {
      // tokens sólo en sessionStorage (más seguro)
      sessionStorage.setItem('leyaps_id_token', data.id_token);
      sessionStorage.setItem('leyaps_access_token', data.access_token);
      if (data.refresh_token) {
        sessionStorage.setItem('leyaps_refresh_token', data.refresh_token);
      }
    } else {
      console.warn('Respuesta de token sin id_token/access_token', data);
    }
  } catch (err) {
    console.error('Error en intercambio de authorization code:', err);
  } finally {
    // Siempre limpiamos el code de la URL
    removeCodeFromUrl();
  }
}

// Logout seguro
function logout() {
  const out = logoutRedirectUri();

  sessionStorage.removeItem('leyaps_id_token');
  sessionStorage.removeItem('leyaps_access_token');
  sessionStorage.removeItem('leyaps_refresh_token');
  updateAuthUI();

  const url = new URL(baseHost() + '/logout');
  url.search = new URLSearchParams({
    client_id: COGNITO.clientId,
    logout_uri: out
  }).toString();

  location.assign(url.toString());
}

/* =======================
   Rutas protegidas
   ======================= */

const PROTECTED_PATHS = ['/privado.html', '/consulta.html'];

function isProtectedRoute() {
  return PROTECTED_PATHS.includes(location.pathname);
}

function enforceAuthGuard() {
  if (isProtectedRoute() && !isLoggedIn()) {
    location.href = '/';
  }
}

/* =======================
   Perfil de usuario (localStorage demo)
   ======================= */

const PROFILE_KEY = 'leyaps_profile';

function loadProfileFromStorage() {
  try {
    const raw = localStorage.getItem(PROFILE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch (_) {
    return {};
  }
}

function saveProfileToStorage(profile) {
  try {
    localStorage.setItem(PROFILE_KEY, JSON.stringify(profile));
  } catch (err) {
    console.warn('No se pudo guardar el perfil en localStorage:', err);
  }
}

function fillProfileForm(tokenPayload, stored) {
  const get = (id) => document.getElementById(id);

  const nameInput = get('profile-name');
  const lastnameInput = get('profile-lastname');
  const phoneInput = get('profile-phone');
  const countryInput = get('profile-country');
  const regionInput = get('profile-region');
  const languageSelect = get('profile-language');
  const userTypeSelect = get('profile-user-type');
  const roleInput = get('profile-role');
  const industryInput = get('profile-industry');
  const companySizeSelect = get('profile-company-size');
  const depthSelect = get('profile-depth');
  const responseSelect = get('profile-response-style');

  if (nameInput) {
    nameInput.value = stored.name || tokenPayload.given_name || '';
  }
  if (lastnameInput) {
    lastnameInput.value = stored.lastname || tokenPayload.family_name || '';
  }
  if (phoneInput) {
    phoneInput.value = stored.phone || tokenPayload.phone_number || '';
  }
  if (countryInput) {
    countryInput.value = stored.country || '';
  }
  if (regionInput) {
    regionInput.value = stored.region || '';
  }
  if (languageSelect) {
    languageSelect.value = stored.language || tokenPayload.locale || '';
  }
  if (userTypeSelect) {
    userTypeSelect.value = stored.userType || '';
  }
  if (roleInput) {
    roleInput.value = stored.role || '';
  }
  if (industryInput) {
    industryInput.value = stored.industry || '';
  }
  if (companySizeSelect) {
    companySizeSelect.value = stored.companySize || '';
  }
  if (depthSelect) {
    depthSelect.value = stored.depth || '';
  }
  if (responseSelect) {
    responseSelect.value = stored.responseStyle || '';
  }

  const topics = stored.topics || [];
  const topicInputs = document.querySelectorAll('input[name="profile-topics"]');
  topicInputs.forEach((input) => {
    input.checked = topics.includes(input.value);
  });
}

function getProfileFormData(tokenPayload) {
  const get = (id) => document.getElementById(id);

  const topicInputs = document.querySelectorAll('input[name="profile-topics"]');
  const topics = Array.from(topicInputs)
    .filter((i) => i.checked)
    .map((i) => i.value);

  const existing = loadProfileFromStorage();

  return {
    name: get('profile-name')?.value?.trim() || '',
    lastname: get('profile-lastname')?.value?.trim() || '',
    phone: get('profile-phone')?.value?.trim() || '',
    country: get('profile-country')?.value?.trim() || '',
    region: get('profile-region')?.value?.trim() || '',
    language: get('profile-language')?.value || '',
    userType: get('profile-user-type')?.value || '',
    role: get('profile-role')?.value?.trim() || '',
    industry: get('profile-industry')?.value?.trim() || '',
    companySize: get('profile-company-size')?.value || '',
    depth: get('profile-depth')?.value || '',
    responseStyle: get('profile-response-style')?.value || '',
    topics,
    createdAt: existing.createdAt || new Date().toISOString(),
    userId: tokenPayload.sub || existing.userId || '',
    email: tokenPayload.email || existing.email || '',
    loginMethod: existing.loginMethod || 'Cognito (email y contraseña)'
  };
}

// Rellenar zona privada con datos del token + perfil
function hydratePrivatePage() {
  if (location.pathname !== '/privado.html' || !isLoggedIn()) return;

  const token = getIdToken();
  const payload = parseJwt(token) || {};

  const usernameEl = document.getElementById('private-username');
  if (usernameEl) {
    usernameEl.textContent = payload.email
      ? payload.email.split('@')[0]
      : 'usuario';
  }

  const emailEl = document.getElementById('profile-email');
  if (emailEl && payload.email) {
    emailEl.textContent = payload.email;
  }

  const idEl = document.getElementById('profile-user-id');
  if (idEl && payload.sub) {
    idEl.textContent = payload.sub;
  }

  const methodEl = document.getElementById('profile-login-method');
  if (methodEl) {
    methodEl.textContent = 'Cognito (email y contraseña)';
  }

  let stored = loadProfileFromStorage();

  if (!stored.createdAt) {
    stored.createdAt = new Date().toISOString();
  }
  stored.userId = stored.userId || payload.sub || '';
  stored.email = stored.email || payload.email || '';
  stored.loginMethod = stored.loginMethod || 'Cognito (email y contraseña)';
  saveProfileToStorage(stored);

  const createdEl = document.getElementById('profile-created-at');
  if (createdEl && stored.createdAt) {
    try {
      createdEl.textContent = new Date(stored.createdAt)
        .toLocaleString('es-CL');
    } catch (_) {
      createdEl.textContent = stored.createdAt;
    }
  }

  fillProfileForm(payload, stored);

  const form = document.getElementById('profile-form');
  if (form && !form.dataset.bound) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const updated = getProfileFormData(payload);
      saveProfileToStorage(updated);
      alert('Perfil guardado correctamente.');
    });
    form.dataset.bound = 'true';
  }
}

/* =======================
   Página de consultas (demo IA)
   ======================= */

function isConsultPage() {
  return location.pathname === '/consulta.html';
}

async function fakeLeyapsAnswer(payload) {
  // Simulador simple de respuesta IA para el MVP
  const { topic, question, depth, channel } = payload;

  const baseIntro = `Esta es una respuesta simulada de Leyaps IA en base a tu consulta laboral.`;
  const topicLine = topic
    ? `\n\n• Tema principal detectado: ${topic}.`
    : '';
  const depthLine = depth
    ? `\n• Nivel de detalle solicitado: ${depth}.`
    : '';
  const channelLine = channel
    ? `\n• Objetivo declarado: ${channel}.`
    : '';

  const pasos = `
\n\nPasos recomendados (demo):
1. Reúne todos los documentos relacionados (contrato, anexos, liquidaciones, comunicaciones por escrito).
2. Anota fechas claves (inicio de contrato, avisos, fecha de término, licencias, etc.).
3. Compara tu caso con los artículos relevantes del Código del Trabajo y dictámenes de la DT (en la versión completa, Leyaps te mostrará estas referencias).
4. Si hay diferencias importantes entre lo que te ofrecen y lo que indica la normativa, considera negociar por escrito.
5. Si la situación es grave o hay vulneración de derechos fundamentales, evalúa asesoría legal con un abogado laboral.

En la versión conectada a la IA, aquí verás:
- Un resumen en simple de tu situación.
- Referencias a artículos y dictámenes aplicables.
- Riesgos y próximos pasos sugeridos según tu perfil (trabajador, empresa o abogado).`;

  const cierre = `\n\n⚠️ Importante: Esta es sólo una simulación de la experiencia. No es asesoría legal personalizada ni reemplaza la revisión de un profesional.`;

  return baseIntro + topicLine + depthLine + channelLine + pasos + cierre;
}

function initConsultPage() {
  if (!isConsultPage() || !isLoggedIn()) return;

  const form = document.getElementById('consult-form');
  const topicSelect = document.getElementById('consult-topic');
  const questionInput = document.getElementById('consult-question');
  const depthSelect = document.getElementById('consult-depth');
  const channelSelect = document.getElementById('consult-channel');
  const statusEl = document.getElementById('consult-status');
  const outputEl = document.getElementById('consult-output');

  if (!form || !questionInput || !outputEl || !statusEl) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const question = questionInput.value.trim();
    if (!question) {
      statusEl.textContent = 'Por favor describe tu situación laboral antes de enviar.';
      return;
    }

    statusEl.textContent = 'Procesando tu consulta (demo)…';
    outputEl.innerHTML = '';

    const payload = {
      topic: topicSelect?.value || '',
      question,
      depth: depthSelect?.value || '',
      channel: channelSelect?.value || ''
    };

    // Simulación de “llamada a la IA”
    const answer = await fakeLeyapsAnswer(payload);

    const pre = document.createElement('pre');
    pre.className = 'answer answer--demo';
    pre.textContent = answer;

    outputEl.innerHTML = '';
    outputEl.appendChild(pre);
    statusEl.textContent = 'Consulta procesada en modo demostración.';

    // Guardar última consulta en localStorage para mostrar historial en el futuro
    try {
      const raw = localStorage.getItem('leyaps_last_consult');
      const prev = raw ? JSON.parse(raw) : [];
      prev.unshift({
        at: new Date().toISOString(),
        ...payload
      });
      localStorage.setItem('leyaps_last_consult', JSON.stringify(prev.slice(0, 10)));
    } catch (_) {
      // si falla, no rompemos nada
    }
  });
}

/* =======================
   Boot: plantillas + búsqueda + auth
   ======================= */
async function boot() {
  await inject('app-header', 'components/header.html');
  await inject('app-footer', 'components/footer.html');

  // Búsqueda demo
  const q  = document.getElementById('q');
  const go = document.getElementById('doSearch');

  go?.addEventListener('click', () => {
    if (!q?.value?.trim()) return q?.focus();
    location.href = 'buscar.html?q=' + encodeURIComponent(q.value.trim());
  });

  document.querySelectorAll('[data-chip]').forEach(b => {
    b.addEventListener('click', () => {
      if (q) {
        q.value = b.dataset.chip;
        q.focus();
      } else {
        location.href =
          'buscar.html?q=' + encodeURIComponent(b.dataset.chip);
      }
    });
  });

  // 1) Si viene ?code= de Cognito, lo cambiamos por tokens
  await handleOAuthCallback();

  // 2) Luego actualizamos la UI según si hay sesión o no
  updateAuthUI();

  // 3) Enforzamos rutas protegidas (privado + consulta)
  enforceAuthGuard();

  // 4) Hidratamos zona privada (si aplica)
  hydratePrivatePage();

  // 5) Inicializamos página de consultas (si aplica)
  initConsultPage();
}

boot();
