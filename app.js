/* Cap 90 — app sans dépendance.
   Tout le contenu (plan + données Actual) arrive dans un « payload ». En ligne il est chiffré
   (data.enc.json, AES-GCM + PBKDF2) et se déchiffre ici, sur le téléphone, avec ta phrase secrète.
   Ce fichier ne contient aucune donnée personnelle. */
'use strict';
(function () {
  const TZ = 'Europe/Paris';
  const NS = 'cap90:';
  const VIEWS = { aujourdhui: "Aujourd'hui", budget: 'Budget', repas: 'Repas', sport: 'Sport', suivi: 'Suivi' };
  const JOURS = ['dimanche', 'lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi'];
  const JC = ['Dim', 'Lun', 'Mar', 'Mer', 'Jeu', 'Ven', 'Sam'];
  const MOIS = ['janvier', 'février', 'mars', 'avril', 'mai', 'juin', 'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre'];
  const MOIS_C = ['janv.', 'févr.', 'mars', 'avr.', 'mai', 'juin', 'juil.', 'août', 'sept.', 'oct.', 'nov.', 'déc.'];

  // ---------- stockage local : peut échouer (navigation privée, aperçu), jamais bloquant ----------
  const store = {
    get(k, d) { try { const v = localStorage.getItem(NS + k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } },
    set(k, v) { try { localStorage.setItem(NS + k, JSON.stringify(v)); } catch (e) { /* tant pis */ } },
    del(k) { try { localStorage.removeItem(NS + k); } catch (e) { /* tant pis */ } },
    keys() { try { return Object.keys(localStorage).filter(k => k.startsWith(NS)).map(k => k.slice(NS.length)); } catch (e) { return []; } },
  };

  // ---------- dates : calendrier de Paris, chaînes AAAA-MM-JJ ----------
  function todayISO() {
    const p = new Intl.DateTimeFormat('en-CA', { timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(new Date());
    const g = t => p.find(x => x.type === t).value;
    return `${g('year')}-${g('month')}-${g('day')}`;
  }
  const toDate = iso => { const [y, m, d] = iso.split('-').map(Number); return new Date(Date.UTC(y, m - 1, d)); };
  const toISO = dt => dt.toISOString().slice(0, 10);
  const addDays = (iso, n) => { const d = toDate(iso); d.setUTCDate(d.getUTCDate() + n); return toISO(d); };
  const diffDays = (a, b) => Math.round((toDate(a) - toDate(b)) / 86400000);
  const weekday = iso => toDate(iso).getUTCDay();
  const mondayOf = iso => addDays(iso, -((weekday(iso) + 6) % 7));
  const daysInMonth = iso => { const [y, m] = iso.split('-').map(Number); return new Date(Date.UTC(y, m, 0)).getUTCDate(); };
  const longDate = iso => { const d = toDate(iso); return `${JOURS[d.getUTCDay()]} ${d.getUTCDate()} ${MOIS[d.getUTCMonth()]}`; };
  const shortDate = iso => { const d = toDate(iso); return `${d.getUTCDate()} ${MOIS_C[d.getUTCMonth()]}`; };
  const hhmm = ts => new Intl.DateTimeFormat('fr-FR', { timeZone: TZ, hour: '2-digit', minute: '2-digit' }).format(new Date(ts));
  function ago(ts) {
    const min = Math.round((Date.now() - new Date(ts).getTime()) / 60000);
    if (min < 2) return "à l'instant";
    if (min < 60) return `il y a ${min} min`;
    const h = Math.round(min / 60);
    if (h < 24) return `il y a ${h} h`;
    return `il y a ${Math.round(h / 24)} j`;
  }

  // ---------- format ----------
  const EUR = new Intl.NumberFormat('fr-FR', { style: 'currency', currency: 'EUR' });
  const EUR0 = new Intl.NumberFormat('fr-FR', { style: 'currency', currency: 'EUR', maximumFractionDigits: 0 });
  const NUM = new Intl.NumberFormat('fr-FR');
  const eur = c => EUR.format((c || 0) / 100);           // centimes → « 12,30 € »
  const euros = e => EUR.format(e || 0);                 // euros → « 12,30 € »
  const euros0 = e => EUR0.format(Math.round(e || 0));   // euros → « 12 € »
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  const sum = arr => arr.reduce((a, b) => a + (b || 0), 0);
  const clamp = (x, a, b) => Math.max(a, Math.min(b, x));
  const pct = (part, whole) => (whole > 0 ? clamp(Math.round((part / whole) * 100), 0, 100) : 0);

  // ---------- état ----------
  const S = { plan: null, snap: null, today: todayISO(), view: 'aujourdhui', sportDay: null, repasType: null, enc: null, open: new Set(), timer: null, audio: null };

  // ---------- chargement + déchiffrement ----------
  const isLocal = () => location.protocol === 'file:' || ['localhost', '127.0.0.1', '[::1]', ''].includes(location.hostname);

  async function loadSource() {
    if (window.__CAP90__) return { payload: window.__CAP90__ };
    if (isLocal()) {
      try {
        const r = await fetch('payload.json', { cache: 'no-store' });
        if (r.ok) return { payload: await r.json() };
      } catch (e) { /* on tente la version chiffrée */ }
    }
    const r = await fetch('data.enc.json', { cache: 'no-store' });
    if (!r.ok) throw new Error('absent');
    return { enc: await r.json() };
  }

  const b64 = s => Uint8Array.from(atob(s), ch => ch.charCodeAt(0));
  async function decrypt(enc, pass) {
    if (!window.crypto || !crypto.subtle) throw new Error('webcrypto');
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt: b64(enc.salt), iterations: enc.iter },
      base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(enc.iv) }, key, b64(enc.ct));
    return JSON.parse(new TextDecoder().decode(pt));
  }

  // ---------- programme ----------
  function prog(iso) {
    const sp = S.plan.sport;
    const j = diffDays(iso, sp.debut) + 1;
    const jj = clamp(j, 1, sp.jours);
    const phase = sp.phases.find(p => jj >= p.de && jj <= p.a) || sp.phases[sp.phases.length - 1];
    const deload = !!(phase.allegee && j >= phase.allegee[0] && j <= phase.allegee[1]);
    const pas = (sp.pas.find(p => jj >= p.de && jj <= p.a) || sp.pas[sp.pas.length - 1]).objectif;
    return { j, phase, deload, pas, week: Math.floor((jj - 1) / 7) + 1, before: j < 1, after: j > sp.jours };
  }

  function sessionOf(iso) {
    const sp = S.plan.sport;
    const p = prog(iso);
    const pi = p.phase.num - 1;
    const id = sp.semaine[String(weekday(iso))];
    const s = sp.seances[id];
    const blocs = (s.blocs || []).map(b => {
      const ex = sp.exercices[b.ex] || { nom: b.ex, variantes: [], consignes: [] };
      let series = b.series ? b.series[pi] : p.phase.series;
      if (p.deload && !s.circuit && series > 1) series -= 1;
      return { id: b.ex, ex, variante: ex.variantes[pi] || '', reps: b.reps[pi], series };
    });
    const circuit = s.circuit ? { tours: Math.max(1, s.circuit.tours[pi] - (p.deload ? 1 : 0)), repos: s.circuit.repos[pi] } : null;
    return { id, nom: s.nom, duree: s.duree, fin: s.fin, blocs, circuit, p, test: (sp.tests.jours || []).includes(p.j) };
  }

  // ---------- repas : semaine A/B à partir du J1 ----------
  const wIndex = iso => Math.floor(diffDays(iso, S.plan.sport.debut) / 7);
  const wType = w => ((((w % 2) + 2) % 2) === 0 ? 'A' : 'B');

  function mealsOf(iso) {
    const r = S.plan.repas;
    const wd = weekday(iso);
    const w = wIndex(iso);
    const tD = wType(wd === 0 ? w + 1 : w); // le batch du dimanche sert la semaine qui commence le lendemain
    const tM = wType(w);
    const day = r.jours[String(wd)];
    const res = slot => {
      if (slot === 'ru') return { kind: 'ru' };
      if (slot && slot.batch) {
        const t = slot.batch === 'dimanche' ? tD : tM;
        const id = r.semaines[t][slot.batch];
        return { kind: 'batch', id, rec: r.recettes[id], portion: slot.portion, batch: slot.batch, type: t };
      }
      if (slot && slot.recette) return { kind: 'recette', id: slot.recette, rec: r.recettes[slot.recette] };
      return null;
    };
    const cookId = wd === 3 ? r.semaines[tM].mercredi : wd === 0 ? r.semaines[tD].dimanche : null;
    return { wd, tD, tM, midi: res(day.midi), diner: res(day.diner), soir: day.soir, cook: cookId ? r.recettes[cookId] : null };
  }

  function nextCourse(iso) {
    const r = S.plan.repas;
    for (let k = 0; k < 7; k++) {
      const d = addDays(iso, k);
      const wd = weekday(d);
      const t = wd === 6 ? wType(wIndex(d) + 1) : wType(wIndex(d)); // samedi : on achète pour le batch du lendemain
      const list = (r.courses[t] || []).find(c => c.jour === wd);
      if (list) return { date: d, k, type: t, list };
    }
    return null;
  }

  // ---------- argent ----------
  function money(iso) {
    const B = S.plan.budget;
    const snap = S.snap;
    const groups = B.groupes || [];
    const varCats = new Set(groups.filter(g => g.variable).flatMap(g => g.categories.map(c => c.nom)));
    const hidden = new Set(groups.filter(g => g.masque).flatMap(g => g.categories.map(c => c.nom)));
    const incomes = new Set(B.revenus || []);
    const tx = (snap && snap.transactions) || [];
    const isSpend = t => t.amount < 0 && !hidden.has(t.category) && !incomes.has(t.category);
    const isVar = t => isSpend(t) && (t.category == null || varCats.has(t.category));
    const todays = tx.filter(t => t.date === iso);
    const spentTodayVar = -sum(todays.filter(isVar).map(t => t.amount));
    const spentTodayVarCat = -sum(todays.filter(t => isVar(t) && t.category != null).map(t => t.amount));
    const mon = mondayOf(iso);
    const spentWeek = -sum(tx.filter(t => t.date >= mon && t.date <= iso && isVar(t)).map(t => t.amount));
    const weekBudget = Math.round(((B.semaine && B.semaine.montant) || 0) * 100);
    const m = iso.slice(0, 7);
    const month = (snap && snap.months && snap.months[m]) || null;
    const catsByName = new Map(((month && month.categories) || []).map(c => [c.name, c]));
    const resteVar = month ? sum([...varCats].map(n => (catsByName.get(n) || {}).balance || 0)) : null;
    const daysLeft = daysInMonth(iso) - Number(iso.slice(8, 10)) + 1;
    // Budget du jour figé au matin : ce qui reste (en ajoutant ce qui a déjà été dépensé aujourd'hui) ÷ jours restants.
    const dayBudget = resteVar == null ? null : Math.max(0, Math.floor((resteVar + spentTodayVarCat) / daysLeft));
    const leftToday = dayBudget == null ? null : dayBudget - spentTodayVar;
    // Comptes « de la semaine » (une carte + le liquide, par exemple). Le solde annoncé par la banque fait foi.
    const sem = B.semaine || {};
    const comptes = sem.comptes || (sem.compte ? [sem.compte] : []);
    const accts = ((snap && snap.accounts) || []).filter(a => comptes.some(c => String(a.name).toLowerCase() === String(c).toLowerCase()));
    const acct = accts[0] || null;
    const acctBal = accts.length ? sum(accts.map(a => (a.bankBalance != null ? a.bankBalance : a.balance))) : null;
    const compte = accts.length ? accts.map(a => a.name).join(' + ') : comptes.join(' + ');
    const bourseCat = (B.revenus || [])[0];
    const allBal = ((snap && snap.accounts) || []).reduce((s, a) => s + (a.bankBalance != null ? a.bankBalance : a.balance), 0);
    const bourse = tx.filter(t => t.category === bourseCat && t.amount > 0 && t.date.slice(0, 7) === m).sort((a, b) => (a.date < b.date ? -1 : 1))[0] || null;
    const stale = snap ? snap.generatedAt.slice(0, 10) < iso : false;
    return { ym: m, B, groups, varCats, hidden, incomes, tx, todays, spentTodayVar, spentWeek, weekBudget, month, catsByName, resteVar, daysLeft, dayBudget, leftToday, compte, acct, acctBal, allBal, bourse, bourseCat, stale, isSpend, isVar };
  }

  // ---------- coquille ----------
  const ICONS = {
    aujourdhui: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    budget: '<rect x="3" y="6" width="18" height="13" rx="2.5"/><path d="M3 10.5h18M15.5 15h2"/>',
    repas: '<path d="M3.5 11.5h17a8.5 8.5 0 0 1-17 0Z"/><path d="M9 7.5c0-1.2 1.2-1.8 1.2-3M13.5 7.5c0-1.2 1.2-1.8 1.2-3"/>',
    sport: '<path d="M6.5 8v8M17.5 8v8M3.5 10.5v3M20.5 10.5v3M6.5 12h11"/>',
    suivi: '<path d="M4 4v16h16"/><path d="m7.5 15 3.5-4.5 3 2.5 4.5-6"/>',
  };

  function renderShell() {
    document.getElementById('app').innerHTML = `
      <header class="top"><div class="top-inner">
        <div class="brand">Cap<span>90</span></div>
        <div class="daycount" id="daycount"></div>
      </div></header>
      <main id="view" tabindex="-1"><p class="loading">Chargement…</p></main>
      <div class="timer" id="timer" hidden></div>
      <div class="toast" id="toast" role="status" hidden></div>
      <nav class="tabs" aria-label="Sections"><div class="tabs-inner">
        ${Object.entries(VIEWS).map(([id, label]) => `<a href="#${id}" data-tab="${id}"><svg viewBox="0 0 24 24" aria-hidden="true">${ICONS[id]}</svg>${label}</a>`).join('')}
      </div></nav>`;
  }

  function markTabs() {
    document.querySelectorAll('[data-tab]').forEach(a => {
      if (a.dataset.tab === S.view) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    });
  }

  function renderDaycount() {
    const el = document.getElementById('daycount');
    if (!el) return;
    const p = prog(S.today);
    if (p.before) el.innerHTML = `<b>J−${1 - p.j}</b><small>avant le départ</small>`;
    else if (p.after) el.innerHTML = '<b>Fini</b><small>90 jours bouclés</small>';
    else el.innerHTML = `<b>J${p.j}<span class="muted">/${S.plan.sport.jours}</span></b><small>Phase ${p.phase.num} · ${esc(p.phase.nom)}</small>`;
  }

  const viewFromHash = () => { const h = (location.hash || '').replace('#', ''); return VIEWS[h] ? h : 'aujourdhui'; };

  function render() {
    const main = document.getElementById('view');
    if (!main || !S.plan) return;
    S.today = todayISO();
    markTabs();
    renderDaycount();
    const fn = { aujourdhui: viewToday, budget: viewBudget, repas: viewRepas, sport: viewSport, suivi: viewSuivi }[S.view];
    try {
      main.innerHTML = fn();
    } catch (e) {
      console.error(e);
      main.innerHTML = `<section class="card"><h2>Cette vue a planté</h2><p class="muted">${esc(e.message)}</p></section>`;
    }
    main.querySelectorAll('details[data-k]').forEach(d => { if (S.open.has(d.dataset.k)) d.open = true; });
    if (S.focusForm) {
      S.focusForm = false;
      const first = main.querySelector('form.edit-form input, form[data-form="cat"] input');
      if (first) { first.focus(); first.scrollIntoView({ block: 'center' }); }
    }
  }

  // ---------- morceaux communs ----------
  function freshness() {
    const snap = S.snap;
    if (!snap) return '<p class="small muted">Pas encore de données Actual : tu vois le plan, pas tes dépenses.</p>';
    const bs = snap.bankSync || {};
    const sync = bs.ran ? (bs.ok ? 'synchro bancaire OK' : 'synchro bancaire en échec') : 'sans synchro bancaire';
    let out = `<p class="small muted">Données Actual ${esc(ago(snap.generatedAt))} (${esc(hhmm(snap.generatedAt))}) · ${sync}</p>`;
    if (bs.ran && !bs.ok) out += '<p class="note warn"><b>Banque à reconnecter ?</b> · Ouvre Actual, onglet Comptes, et relance la synchro. Les accès bancaires expirent tous les 90 à 180 jours.</p>';
    return out + actionsRow();
  }

  function txRow(t) {
    const cat = t.category ? `<span class="chip">${esc(t.category)}</span>` : '<span class="chip warn">à classer</span>';
    const sign = t.amount > 0 ? '+' : '';
    return `<li><div class="grow"><div class="title">${esc(t.payee || '—')}</div><div class="meta">${cat} · ${esc(t.account)}</div></div><div class="amount ${t.amount < 0 ? 'neg' : 'pos'}">${sign}${eur(t.amount)}</div></li>`;
  }

  function checkItem(id, attrs, checked, label, detail, right) {
    return `<li><label class="check"><input type="checkbox" id="${esc(id)}" ${attrs} ${checked ? 'checked' : ''}><span class="grow"><span class="label">${esc(label)}</span>${detail ? `<span class="detail">${esc(detail)}</span>` : ''}</span>${right || ''}</label></li>`;
  }

  const kcalOf = (slot, r) => (!slot ? 0 : slot.kind === 'ru' ? r.restoU.kcal : slot.rec.kcal);
  const protOf = (slot, r) => (!slot ? 0 : slot.kind === 'ru' ? r.restoU.prot : slot.rec.prot);
  function slotLine(slot, r, moment) {
    if (!slot) return ['—', ''];
    if (slot.kind === 'ru') return ['Resto U · 1 €', `${esc(r.restoU.court)} · ${r.restoU.kcal} kcal · ${r.restoU.prot} g`];
    const rec = slot.rec;
    if (slot.kind === 'batch') return [rec.nom, `${moment === 'midi' ? 'Boîte · batch' : 'Batch'} du ${esc(slot.batch)} · portion ${esc(slot.portion)} · ${rec.kcal} kcal · ${rec.prot} g`];
    return [rec.nom, `Express · ${esc(rec.temps)} · ${rec.kcal} kcal · ${rec.prot} g`];
  }

  // ---------- modifier depuis l'app : workflow GitHub edit.yml → Actual ----------
  // Le jeton (fine-grained, « Actions : lecture et écriture » sur le seul repo) reste sur ce téléphone.
  const GH = {
    token: () => store.get('gh', null),
    repo: () => (S.plan && S.plan.budget && S.plan.budget.github && S.plan.budget.github.repo) || null,
    ready: () => Boolean(GH.token() && GH.repo()),
    async call(path, opts) {
      const t = GH.token();
      if (!t) throw Object.assign(new Error('jeton'), { status: 0 });
      const headers = { Authorization: 'Bearer ' + t, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
      if (opts && opts.body) headers['Content-Type'] = 'application/json';
      const r = await fetch('https://api.github.com' + path, Object.assign({}, opts, { headers }));
      if (!r.ok) throw Object.assign(new Error('http'), { status: r.status });
      return r.status === 204 ? null : r.json();
    },
    dispatch: (workflow, inputs) => GH.call(`/repos/${GH.repo()}/actions/workflows/${workflow}/dispatches`, { method: 'POST', body: JSON.stringify({ ref: 'main', inputs }) }),
  };

  // write = l'appel lance un workflow (dispatch) : un 403 veut alors dire « lecture seule ».
  function ghError(e, write) {
    if (e.status === 403 && write) return "Écriture refusée : sur GitHub, passe la permission Actions du jeton en « Read and write ». Inutile de le recréer.";
    if (e.status === 401) return 'Jeton refusé ou expiré : recrée-le et colle-le à nouveau.';
    if (e.status === 403) return 'Jeton refusé : il lui faut « Actions : Read and write » sur le repo.';
    if (e.status === 404) return "Repo introuvable avec ce jeton : dans « Repository access », choisis le repo de l'app.";
    if (e.status === 422) return 'GitHub a refusé la demande. Réessaie dans un instant.';
    return 'Envoi impossible : vérifie ta connexion et réessaie.';
  }

  // Résultat du dernier envoi, gardé pour l'afficher dans Suivi (une notification se rate vite).
  function noteResult(label, err) {
    store.set('gh:last', { at: new Date().toISOString(), label, ok: !err, status: err ? err.status || 0 : 204, msg: err ? ghError(err, true) : '' });
  }

  function whenLabel(ts) {
    const d = new Intl.DateTimeFormat('en-CA', { timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date(ts));
    return d === S.today ? `à ${hhmm(ts)}` : `le ${shortDate(d)} à ${hhmm(ts)}`;
  }

  // Vrai test : lecture (le workflow existe) puis écriture (lance ping.yml, sans effet sur Actual).
  async function testConnection() {
    try {
      await GH.call(`/repos/${GH.repo()}/actions/workflows/edit.yml`);
    } catch (e) {
      noteResult('Test de connexion', e);
      toast(ghError(e), 'bad');
      render();
      return false;
    }
    try {
      await GH.dispatch('ping.yml', {});
      noteResult('Test de connexion (lecture et écriture)');
      toast('Connexion OK, en lecture et en écriture : tes envois partiront.', 'ok');
      render();
      return true;
    } catch (e) {
      noteResult('Test de connexion', e);
      toast(e.status === 403 ? "Lecture OK, mais écriture refusée : sur GitHub, passe la permission Actions du jeton en « Read and write »." : ghError(e, true), 'bad');
      render();
      return false;
    }
  }

  function toast(msg, kind) {
    const el = document.getElementById('toast');
    if (!el) return;
    el.className = 'toast ' + (kind || '');
    el.textContent = msg;
    el.hidden = false;
    clearTimeout(S.toastTimer);
    S.toastTimer = setTimeout(() => { el.hidden = true; }, kind === 'bad' ? 12000 : 6000);
  }

  // Modifications envoyées que les données affichées ne contiennent pas encore.
  function pendingOps() {
    const gen = S.snap ? new Date(S.snap.generatedAt).getTime() : 0;
    const dayAgo = Date.now() - 86400000;
    return store.get('ops:sent', []).filter(s => {
      const t = new Date(s.at).getTime();
      return t > dayAgo && t > gen - 5000;
    });
  }
  const pendingList = () => pendingOps().flatMap(p => p.ops || []);

  async function sendOps(ops, label) {
    if (!GH.ready()) {
      toast("Ajoute d'abord ton jeton GitHub : onglet Suivi, « Modifier depuis l'app ».", 'warn');
      return false;
    }
    try {
      await GH.dispatch('edit.yml', { ops: JSON.stringify(ops) });
      const sent = store.get('ops:sent', []);
      sent.push({ at: new Date().toISOString(), label, ops });
      store.set('ops:sent', sent.slice(-40));
      noteResult(label);
      toast(`${label} : envoyé. Visible ici d'ici 2 à 4 minutes.`, 'ok');
      schedulePendingRefresh();
      return true;
    } catch (e) {
      noteResult(label, e);
      toast(ghError(e, true), 'bad');
      return false;
    }
  }

  async function bankSync(btn) {
    if (!GH.ready()) {
      toast("Ajoute d'abord ton jeton GitHub : onglet Suivi, « Modifier depuis l'app ».", 'warn');
      return;
    }
    const recent = store.get('ops:sent', []).filter(x => x.label === 'Synchro bancaire' && Date.now() - new Date(x.at).getTime() < 600000).pop();
    if (recent) {
      toast(`Synchro déjà lancée ${whenLabel(recent.at)} : les données arrivent d'ici 2 à 3 minutes. Chaque synchro compte parmi les 4 accès bancaires du jour.`, 'warn');
      return;
    }
    if (btn) { btn.disabled = true; btn.textContent = 'Synchro…'; }
    try {
      await GH.dispatch('sync.yml', { bank_sync: 'true' });
      const sent = store.get('ops:sent', []);
      sent.push({ at: new Date().toISOString(), label: 'Synchro bancaire', ops: [] });
      store.set('ops:sent', sent.slice(-40));
      noteResult('Synchro bancaire');
      toast('Synchro bancaire lancée : nouvelles données d’ici 2 à 3 minutes.', 'ok');
      schedulePendingRefresh();
    } catch (e) {
      noteResult('Synchro bancaire', e);
      toast(ghError(e, true), 'bad');
    }
  }

  // Recharge les données (chiffrées en ligne) sans recharger la page.
  async function refreshData(silent) {
    if (window.__CAP90__) return;
    try {
      let payload = null;
      if (isLocal()) {
        const r = await fetch('payload.json?t=' + Date.now(), { cache: 'no-store' });
        if (r.ok) payload = await r.json();
      }
      if (!payload) {
        const r = await fetch('data.enc.json?t=' + Date.now(), { cache: 'no-store' });
        if (!r.ok) throw new Error('absent');
        const pass = store.get('pass', null) || S.pass;
        if (!pass) throw new Error('pass');
        payload = await decrypt(await r.json(), pass);
      }
      const before = S.snap && S.snap.generatedAt;
      S.plan = payload.plan || S.plan;
      S.snap = payload.snapshot || null;
      S.loadedAt = Date.now();
      if (!S.form) render();
      if (!silent) toast(before && S.snap && S.snap.generatedAt === before ? 'Pas encore de nouvelles données.' : 'Données à jour.', 'ok');
    } catch (e) {
      if (!silent) toast("Impossible d'actualiser pour l'instant.", 'bad');
    }
  }

  // Tant que des modifications sont en route, on revérifie toutes les 45 s (10 fois au plus).
  function schedulePendingRefresh() {
    clearTimeout(S.pendingTimer);
    let n = 0;
    const tick = async () => {
      if (++n > 10 || !pendingOps().length) return;
      if (!document.hidden) await refreshData(true);
      S.pendingTimer = setTimeout(tick, 45000);
    };
    S.pendingTimer = setTimeout(tick, 45000);
  }

  function actionsRow() {
    const pend = pendingOps();
    const banner = pend.length
      ? `<p class="note"><b>${pend.length} modification${pend.length > 1 ? 's' : ''} en cours</b> · ${esc(pend.map(p => p.label).join(', '))}</p>`
      : '';
    return `${banner}<div class="btn-row"><button type="button" class="btn small-btn" data-act="refresh">Actualiser</button>${GH.ready() ? '<button type="button" class="btn small-btn" data-act="banksync">Synchroniser la banque</button>' : ''}</div>`;
  }

  // Catégories de dépenses proposées dans les formulaires : celles du plan, puis celles créées dans Actual.
  function expenseCategoryNames() {
    const names = [];
    for (const g of S.plan.budget.groupes || []) for (const c of g.categories) names.push(c.nom);
    const m = S.snap && S.snap.months && S.snap.months[S.today.slice(0, 7)];
    const incomes = new Set(S.plan.budget.revenus || []);
    for (const c of (m && m.categories) || []) if (!names.includes(c.name) && !incomes.has(c.name) && c.name !== 'Starting Balances') names.push(c.name);
    return names;
  }

  const options = (list, selected) => list.map(v => `<option${v === selected ? ' selected' : ''}>${esc(v)}</option>`).join('');
  const accountNames = () => ((S.snap && S.snap.accounts) || []).map(a => a.name);

  function subForm(s) {
    const accounts = accountNames();
    const freq = s && s.frequency === 'yearly' ? 'yearly' : 'monthly';
    const v = s
      ? { name: s.name, amount: Math.abs(s.amount) / 100, day: s.day === -1 ? 31 : s.day || 1, account: s.account || accounts[0], category: s.category || 'Abonnements', approx: Boolean(s.approx), payee: '' }
      : { name: '', amount: '', day: toDate(S.today).getUTCDate(), account: accounts[0] || '', category: 'Abonnements', approx: false, payee: '' };
    return `<form class="edit-form" data-form="sub" data-id="${s ? esc(s.id) : ''}">
      <h3>${s ? `Modifier « ${esc(s.name)} »` : 'Nouvel abonnement'}</h3>
      <div class="field"><label for="sf-name">Nom</label><input class="input" id="sf-name" name="name" maxlength="60" required value="${esc(v.name)}" placeholder="Netflix, Spotify, forfait…"></div>
      <div class="form-row">
        <div class="field"><label for="sf-amount">Montant (€)</label><input class="input" id="sf-amount" name="amount" type="text" inputmode="decimal" autocomplete="off" required value="${v.amount}"></div>
        <div class="field"><label for="sf-day">Jour du mois</label><input class="input" id="sf-day" name="day" type="number" inputmode="numeric" min="1" max="31" required value="${v.day}"></div>
      </div>
      <div class="form-row">
        <div class="field"><label for="sf-freq">Rythme</label><select class="input" id="sf-freq" name="frequency"><option value="monthly"${freq === 'monthly' ? ' selected' : ''}>Tous les mois</option><option value="yearly"${freq === 'yearly' ? ' selected' : ''}>Tous les ans</option></select></div>
        <div class="field"><label for="sf-month">Mois (si annuel)</label><select class="input" id="sf-month" name="month">${MOIS.map((m, i) => `<option value="${i + 1}"${i === toDate(S.today).getUTCMonth() ? ' selected' : ''}>${m}</option>`).join('')}</select></div>
      </div>
      <div class="form-row">
        <div class="field"><label for="sf-account">Compte</label><select class="input" id="sf-account" name="account">${options(accounts, v.account)}</select></div>
        <div class="field"><label for="sf-cat">Catégorie</label><select class="input" id="sf-cat" name="category">${options(expenseCategoryNames(), v.category)}</select></div>
      </div>
      ${s ? '' : '<div class="field"><label for="sf-payee">Libellé sur le relevé (facultatif)</label><input class="input" id="sf-payee" name="payee" maxlength="60" placeholder="ex. netflix"><span class="small muted">Le mot qui apparaît sur ton relevé : il sert à relier le prélèvement.</span></div>'}
      <label class="check"><input type="checkbox" id="sf-approx" name="approx"${v.approx ? ' checked' : ''}><span class="grow"><span class="label">Montant qui varie un peu</span></span></label>
      <label class="check"><input type="checkbox" id="sf-adjust" name="adjustBudget" checked><span class="grow"><span class="label">Ajuster le budget de la catégorie</span><span class="detail">Ce mois et les 3 suivants</span></span></label>
      <div class="btn-row"><button class="btn primary" type="submit">${s ? 'Enregistrer' : 'Ajouter'}</button><button class="btn ghost" type="button" data-act="form-cancel">Annuler</button>${s ? `<button class="btn ghost danger" type="button" data-sub-del="${esc(s.id)}">Supprimer</button>` : ''}</div>
    </form>`;
  }

  function subsBlock() {
    const subs = (S.snap && S.snap.subscriptions) || [];
    if (!S.snap) return '';
    const ops = pendingList();
    const deleted = new Set(ops.filter(o => o.op === 'delete-sub').map(o => o.id));
    const updated = new Set(ops.filter(o => o.op === 'update-sub').map(o => o.id));
    const added = ops.filter(o => o.op === 'add-sub');
    const monthly = s => (s.frequency === 'yearly' ? Math.abs(s.amount) / 12 : Math.abs(s.amount));
    const total = sum(subs.filter(s => !deleted.has(s.id)).map(monthly)) + sum(added.map(o => Math.round((o.frequency === 'yearly' ? o.amount / 12 : o.amount) * 100)));
    const when = s => (s.day === -1 ? 'fin du mois' : s.day ? `le ${s.day}` : '');
    const rows = subs.map(s => {
      const f = S.form;
      if (f && f.type === 'sub' && f.id === s.id) return `<li class="form-li">${subForm(s)}</li>`;
      if (f && f.type === 'del' && f.id === s.id) {
        return `<li class="form-li"><div class="grow"><b>Supprimer « ${esc(s.name)} » ?</b><div class="meta">Le budget de ${esc(s.category || 'sa catégorie')} baisse d'autant.</div><div class="btn-row"><button type="button" class="btn primary danger-bg" data-del-confirm="${esc(s.id)}">Oui, supprimer</button><button type="button" class="btn ghost" data-act="form-cancel">Annuler</button></div></div></li>`;
      }
      const isDel = deleted.has(s.id);
      const chip = isDel ? ' <span class="chip warn">suppression en cours</span>' : updated.has(s.id) ? ' <span class="chip accent">modification en cours</span>' : '';
      const next = s.nextDate ? ` · prochain ${esc(shortDate(s.nextDate))}` : '';
      return `<li class="${isDel ? 'struck' : ''}"><div class="grow"><div class="title">${esc(s.name)}${chip}</div><div class="meta"><span class="chip">${esc(s.category || 'sans catégorie')}</span> · ${esc(s.account || '')} · ${s.frequency === 'yearly' ? 'par an' : 'par mois'} ${when(s)}${next}</div></div><div class="amount">${s.approx ? '≈ ' : ''}${eur(s.amount)}</div>${isDel ? '' : `<button type="button" class="btn ghost small-btn" data-sub-edit="${esc(s.id)}" aria-label="Modifier ${esc(s.name)}">Modifier</button>`}</li>`;
    });
    const addedRows = added.map(o => `<li><div class="grow"><div class="title">${esc(o.name)} <span class="chip accent">ajout en cours</span></div><div class="meta"><span class="chip">${esc(o.category)}</span> · ${esc(o.account)} · le ${o.day}</div></div><div class="amount">−${euros(o.amount)}</div></li>`);
    const addForm = S.form && S.form.type === 'sub' && !S.form.id ? subForm(null) : '<div class="btn-row"><button type="button" class="btn" data-act="sub-new">Ajouter un abonnement</button></div>';
    return `<section aria-labelledby="ab-h"><div class="group-head"><h2 id="ab-h">Abonnements et prélèvements</h2><span class="num">${eur(total)} par mois</span></div>
      ${rows.length || addedRows.length ? `<ul class="list">${rows.join('')}${addedRows.join('')}</ul>` : '<p class="small muted">Aucun abonnement enregistré dans Actual pour l\'instant.</p>'}
      ${addForm}</section>`;
  }

  function txForm() {
    const accounts = accountNames();
    const def = accounts.find(a => /liquide/i.test(a)) || accounts[0] || '';
    const cats = expenseCategoryNames();
    const varFirst = [...cats.filter(c => money(S.today).varCats.has(c)), ...cats.filter(c => !money(S.today).varCats.has(c))];
    return `<form class="edit-form" data-form="tx">
      <h3>Nouvelle dépense</h3>
      <div class="form-row">
        <div class="field"><label for="tf-amount">Montant (€)</label><input class="input" id="tf-amount" name="amount" type="text" inputmode="decimal" autocomplete="off" required></div>
        <div class="field"><label for="tf-date">Date</label><input class="input" id="tf-date" name="date" type="date" required value="${S.today}" max="${S.today}"></div>
      </div>
      <div class="form-row">
        <div class="field"><label for="tf-cat">Catégorie</label><select class="input" id="tf-cat" name="category">${options(varFirst, 'Courses')}</select></div>
        <div class="field"><label for="tf-account">Payé avec</label><select class="input" id="tf-account" name="account">${options(accounts, def)}</select></div>
      </div>
      <div class="field"><label for="tf-payee">Où (facultatif)</label><input class="input" id="tf-payee" name="payee" maxlength="60" placeholder="Lidl, marché, kebab…"></div>
      <p class="small muted">Pour le liquide surtout : les paiements par carte arrivent tout seuls avec la synchro bancaire.</p>
      <div class="btn-row"><button class="btn primary" type="submit">Ajouter</button><button class="btn ghost" type="button" data-act="form-cancel">Annuler</button></div>
    </form>`;
  }

  function ghBlock() {
    const repo = GH.repo();
    if (!repo || window.__CAP90__) return '';
    if (GH.token()) {
      const last = store.get('gh:last', null);
      const lastLine = !last ? '<p class="small muted">Aucun envoi pour l\'instant. « Tester la connexion » vérifie la lecture et l\'écriture.</p>'
        : last.ok ? `<p class="small muted">Dernier envoi réussi : ${esc(last.label)}, ${esc(whenLabel(last.at))}.</p>`
          : `<p class="note warn"><b>Dernier envoi refusé, ${esc(whenLabel(last.at))}</b> · ${esc(last.msg)}</p>`;
      return `<section aria-labelledby="gh-h"><h2 id="gh-h">Modifier depuis l'app</h2>
        <p class="note"><b>Jeton enregistré</b> · Abonnements, montants et dépenses en liquide partent vers Actual. Le jeton reste sur ce téléphone.</p>
        ${lastLine}
        <div class="btn-row"><button type="button" class="btn" data-act="gh-test">Tester la connexion</button><button type="button" class="btn ghost" data-act="gh-forget">Oublier le jeton</button></div></section>`;
    }
    return `<section aria-labelledby="gh-h"><h2 id="gh-h">Modifier depuis l'app</h2>
      <p class="small muted">Pour ajouter un abonnement, changer un montant ou noter une dépense en liquide, l'app a besoin d'un jeton GitHub limité à ton repo. Une seule fois, sur ce téléphone :</p>
      <ol class="steps">
        <li>Ouvre <a href="https://github.com/settings/personal-access-tokens/new" target="_blank" rel="noopener">github.com/settings/personal-access-tokens/new</a>.</li>
        <li>Nom : « Cap 90 téléphone ». Expiration : 90 jours ou plus.</li>
        <li>Repository access : <b>Only select repositories</b>, puis <b>${esc(repo)}</b>.</li>
        <li>Permissions, Repository : <b>Actions → Read and write</b>. Rien d'autre.</li>
        <li>Generate token, copie-le et colle-le ici.</li>
      </ol>
      <form class="inline-form" data-form="gh"><div class="field"><label for="gh-token">Jeton</label><input class="input" id="gh-token" type="password" autocomplete="off" required placeholder="github_pat_…"></div><button class="btn primary" type="submit">Enregistrer</button></form>
    </section>`;
  }

  // ---------- AUJOURD'HUI ----------
  function viewToday() {
    const iso = S.today;
    const p = prog(iso);
    const title = p.before ? 'Mise en place' : p.after ? 'Les 90 jours sont bouclés' : `Jour ${p.j}`;
    const out = [`<section><p class="eyebrow">${esc(longDate(iso))}</p><h1>${title}</h1></section>`];
    out.push(moneyCard(iso));
    if (needsPont(iso, p)) out.push(pontBlock(iso));
    if (p.before) out.push(miseEnRouteBlock(true));
    out.push(p.before ? startBlock() : mealsBlock(iso, p));
    out.push(sessionCard(iso, p));
    out.push(checklistBlock(iso, p));
    if (!p.before) out.push(miseEnRouteBlock(false));
    return out.join('');
  }

  function moneyCard(iso) {
    const M = money(iso);
    const B = M.B;
    if (!S.snap || !M.month) {
      return `<section class="card" aria-labelledby="m-h"><p class="hero-label" id="m-h">Ta semaine sur ${esc(M.compte || 'ton compte')}</p>
        <div class="hero-num">${euros0(B.semaine.montant)}</div>
        <p class="hero-sub">${esc(B.semaine.regle)}</p>${freshness()}</section>`;
    }
    // On ne peut pas dépenser plus que ce qu'il y a sur le compte de la semaine, même si l'enveloppe le permet.
    const capped = M.acctBal != null && M.leftToday > 0 && M.acctBal < M.leftToday;
    const left = capped ? Math.max(0, M.acctBal) : M.leftToday;
    const state = left < 0 ? 'bad' : capped || (M.dayBudget > 0 && left < M.dayBudget * 0.25) ? 'warn' : 'ok';
    const weekState = M.spentWeek > M.weekBudget ? 'bad' : pct(M.spentWeek, M.weekBudget) >= 80 ? 'warn' : 'ok';
    const pendTx = pendingList().filter(o => o.op === 'add-tx' && o.date === iso)
      .map(o => `<li><div class="grow"><div class="title">${esc(o.payee || o.category || 'Dépense')} <span class="chip accent">en cours</span></div><div class="meta"><span class="chip">${esc(o.category || 'à classer')}</span> · ${esc(o.account)}</div></div><div class="amount neg">${eur(Math.round(o.amount * 100))}</div></li>`).join('');
    const rows = M.todays.filter(t => t.amount !== 0 && !M.hidden.has(t.category)).map(txRow).join('') + pendTx;
    const addTx = S.form && S.form.type === 'tx' ? txForm() : '<div class="btn-row"><button type="button" class="btn" data-act="tx-new">Ajouter une dépense</button></div>';
    const bourse = M.bourse ? `reçue le ${toDate(M.bourse.date).getUTCDate()}` : 'pas encore';
    const capNote = capped
      ? `<p class="note warn"><b>Limité par ton solde ${esc(M.compte)}</b> · L'enveloppe du jour est de ${eur(M.leftToday)}, mais il n'y a que ${eur(M.acctBal)} sur le compte${M.bourse ? '' : ' : la bourse n\'est pas encore arrivée'}.</p>`
      : '';
    return `<section class="card" aria-labelledby="m-h">
      <p class="hero-label" id="m-h">${left < 0 ? "Dépassé aujourd'hui de" : "Tu peux encore dépenser aujourd'hui"}</p>
      <div class="hero-num ${state}">${eur(Math.abs(left))}</div>
      <p class="hero-sub num">Budget du jour ${eur(M.dayBudget)} · dépensé ${eur(M.spentTodayVar)} · encore ${M.daysLeft} j ce mois-ci</p>
      ${capNote}
      <div>
        <div class="group-head"><b class="small">Semaine (depuis lundi)</b><span>${eur(M.spentWeek)} / ${eur(M.weekBudget)}</span></div>
        <div class="meter ${weekState}"><span style="width:${pct(M.spentWeek, M.weekBudget)}%"></span></div>
      </div>
      <dl class="kv">
        <div><dt>${esc(M.compte || 'Compte')}</dt><dd>${M.acctBal != null ? eur(M.acctBal) : '—'}</dd></div>
        <div><dt>Reste du mois</dt><dd>${eur(M.resteVar)}</dd></div>
        <div><dt>${esc(M.bourseCat || 'Bourse')}</dt><dd>${bourse}</dd></div>
      </dl>
      ${rows ? `<ul class="list">${rows}</ul>` : `<p class="small muted">Aucune dépense aujourd'hui${M.stale ? ' dans les dernières données' : ''}.</p>`}
      ${addTx}
      ${freshness()}
    </section>`;
  }

  function mealsBlock(iso, p) {
    const r = S.plan.repas;
    const m = mealsOf(iso);
    const pd = r.recettes['bol-avoine'];
    const co = r.recettes.collation;
    const [mt, ms] = slotLine(m.midi, r, 'midi');
    const [dt, ds] = slotLine(m.diner, r, 'diner');
    const line = (when, t, s) => `<li><span class="when">${esc(when)}</span><div class="what"><b>${esc(t)}</b><span>${s}</span></div></li>`;
    const kcal = pd.kcal + co.kcal + kcalOf(m.midi, r) + kcalOf(m.diner, r);
    const prot = pd.prot + co.prot + protOf(m.midi, r) + protOf(m.diner, r);
    const tonight = m.soir ? `<p class="note"><b>Ce soir</b> · ${esc(m.soir)}${m.cook ? ` Au programme : ${esc(m.cook.nom)}.` : ''}</p>` : '';
    const before = p.before ? '<p class="note warn"><b>Avant J1</b> · Course 1 samedi soir avec le stock de départ, dès que la bourse est tombée. Dimanche soir, premier batch.</p>' : '';
    return `<section aria-labelledby="r-h">
      <div class="group-head"><h2 id="r-h">Au menu</h2><span class="chip accent">Semaine ${m.tM}</span></div>
      <ol class="meals">
        ${line('7h30', pd.nom, `${pd.kcal} kcal · ${pd.prot} g`)}
        ${line('12h', mt, ms)}
        ${line('16h30', co.nom, `${co.kcal} kcal · ${co.prot} g`)}
        ${line('20h', dt, ds)}
      </ol>
      <p class="small muted num">≈ ${NUM.format(kcal)} kcal · ${prot} g de protéines</p>
      ${tonight}${before}
      <div class="btn-row"><a class="btn" href="#repas">Recettes et listes de courses</a></div>
    </section>`;
  }

  // Tant que la bourse du mois n'est pas tombée : ce qu'il reste, et de quoi tenir.
  const needsPont = (iso, p) => (S.snap ? !money(iso).bourse : p.before);

  function pontBlock(iso) {
    const pont = S.plan.repas.courses && S.plan.repas.courses.pont;
    if (!pont) return '';
    const M = money(iso);
    const st = store.get('courses:pont', {});
    const total = sum(pont.articles.map(a => a.prix));
    const avail = S.snap ? `<div class="hero-num ${M.allBal < 2000 ? 'warn' : ''}">${eur(M.allBal)}</div><p class="hero-sub">sur tous tes comptes, liquide compris. La bourse arrive ${esc(M.B.revenu.versement.split(',')[0])}.</p>` : '';
    return `<section class="card" aria-labelledby="pt-h">
      <p class="hero-label" id="pt-h">Jusqu'à la bourse</p>${avail}
      <h2>${esc(pont.titre)} · ≈ ${euros(total)}</h2>
      <p class="small muted">${esc(pont.texte)}</p>
      <ul class="checks">${pont.articles.map((a, i) => checkItem(`pt-${i}`, `data-course="pont" data-i="${i}"`, st[i], a.nom, '', `<span class="price">${euros(a.prix)}</span>`)).join('')}</ul>
      <p class="small muted">Pas de loyer ni de grosse course avant la bourse : seulement ce kit, et le Resto U le soir à 1 €.</p>
    </section>`;
  }

  // Montant du plan pour une catégorie un mois donné (avec les surcharges du mois).
  function planBudget(B, name, month) {
    const over = (B.mois && B.mois[month]) || {};
    if (Object.prototype.hasOwnProperty.call(over, name)) return over[name];
    for (const g of B.groupes || []) for (const c of g.categories) if (c.nom === name) return c.budget;
    return 0;
  }

  // Avant le J1 : pas de menu fictif, juste les trois étapes du démarrage.
  function startBlock() {
    const r = S.plan.repas;
    const debut = S.plan.sport.debut;
    const first = r.recettes[r.semaines.A.dimanche];
    const steps = [
      [addDays(debut, -2), 'Course 1 (semaine A) + stock de départ', 'Le soir, dès que la bourse est tombée. Liste dans l\'onglet Repas.'],
      [addDays(debut, -1), `Premier batch : ${first.nom}`, `${first.portions} portions, ${first.temps}. Tu en manges une le soir même.`],
      [debut, 'J1 : tests, pesée, première séance', 'Boîte du batch à midi, collation fromage blanc, Resto U le soir.'],
    ];
    const rows = steps.map(([d, t, s]) => `<li><span class="when">${esc(JC[weekday(d)])}</span><div class="what"><b>${esc(t)}</b><span>${esc(longDate(d))} · ${esc(s)}</span></div></li>`).join('');
    return `<section aria-labelledby="r-h"><div class="group-head"><h2 id="r-h">Le démarrage</h2><span class="chip accent">Semaine A</span></div>
      <ol class="meals">${rows}</ol>
      <p class="small muted">D'ici là, mange ce que tu as et évite la livraison : chaque euro compte avant la bourse.</p>
      <div class="btn-row"><a class="btn" href="#repas">Recettes et listes de courses</a></div></section>`;
  }

  function sessionCard(iso, p) {
    const s = sessionOf(iso);
    const sub = p.before
      ? 'Marche 30 min par jour et prépare ton sac à dos : 6 à 8 kg de livres ou de bouteilles.'
      : `${s.duree} min · ${s.p.deload ? 'semaine allégée · ' : ''}phase ${s.p.phase.num}, ${esc(s.p.phase.nom.toLowerCase())}`;
    const test = s.test ? '<p class="note"><b>Jour de test</b> · Fais les tests de l\'onglet Suivi avant la séance.</p>' : '';
    return `<section class="card" aria-labelledby="s-h">
      <p class="hero-label" id="s-h">${p.before ? 'Avant le J1' : 'Séance du jour'}</p>
      <h2>${esc(p.before ? 'Prépare le terrain' : s.nom)}</h2>
      <p class="small muted">${sub}</p>${test}
      <div class="btn-row"><a class="btn primary" href="#sport">${p.before ? 'Voir le programme' : 'Ouvrir la séance'}</a><span class="chip">${NUM.format(p.pas)} pas</span></div>
    </section>`;
  }

  const DAY_ITEMS = p => [
    ['seance', 'Séance faite', ''],
    ['pas', `${NUM.format(p.pas)} pas`, 'Marche au lieu du tram pour tout trajet de moins de 20 min'],
    ['prot', 'Les 4 repas du plan', '≈ 140 g de protéines'],
    ['eau', "2,5 L d'eau", ''],
    ['sommeil', '7 h de sommeil', ''],
    ['zero', '0 € de fast-food et de distributeur', ''],
  ];

  function streak(iso) {
    let n = 0;
    for (let k = 1; k <= 120; k++) {
      const st = store.get('jour:' + addDays(iso, -k), null);
      if (!st || Object.values(st).filter(Boolean).length < 5) break;
      n++;
    }
    return n;
  }

  function checklistBlock(iso, p) {
    const items = DAY_ITEMS(p);
    const st = store.get('jour:' + iso, {});
    const done = items.filter(([k]) => st[k]).length;
    const n = streak(iso);
    return `<section aria-labelledby="c-h">
      <div class="group-head"><h2 id="c-h">Ta journée</h2><span class="num">${done}/${items.length}</span></div>
      <ul class="checks">${items.map(([k, l, d]) => checkItem(`jour-${k}`, `data-day="${iso}" data-key="${k}"`, st[k], l, d)).join('')}</ul>
      <p class="small muted">${n > 0 ? `Série en cours : ${n} jour${n > 1 ? 's' : ''} à 5 cases ou plus.` : 'Une journée réussie = au moins 5 cases.'}</p>
    </section>`;
  }

  function miseEnRouteBlock(top) {
    const items = (S.plan.budget && S.plan.budget.miseEnRoute) || [];
    if (!items.length) return '';
    const st = store.get('miseEnRoute', {});
    const done = items.filter(i => st[i.id]).length;
    if (done === items.length && !top) return '';
    return `<details data-k="mer" ${top ? 'open' : ''}><summary><span class="sum-main"><b>Mise en route</b><span>${done}/${items.length} fait${done > 1 ? 's' : ''}</span></span></summary>
      <div class="body"><ul class="checks">${items.map(i => checkItem(`mer-${i.id}`, `data-mer="${esc(i.id)}"`, st[i.id], i.titre, i.detail)).join('')}</ul></div></details>`;
  }

  // ---------- BUDGET ----------
  function viewBudget() {
    const iso = S.today;
    const M = money(iso);
    const B = M.B;
    const mName = MOIS[toDate(iso).getUTCMonth()];
    const visible = B.groupes.filter(g => !g.masque);
    const planVar = sum(B.groupes.filter(g => g.variable).flatMap(g => g.categories.map(c => planBudget(B, c.nom, M.ym))));
    const planTotal = sum(B.groupes.flatMap(g => g.categories.map(c => planBudget(B, c.nom, M.ym))));
    const budgetedTotal = M.month ? sum(M.month.categories.map(c => c.budgeted || 0)) : null;
    const head = M.resteVar != null
      ? `<h1>${eur(M.resteVar)} pour vivre</h1><p class="lede">Ce qui reste en courses, Resto U, laverie et plaisirs jusqu'à la fin de ${mName}. Soit ${eur(Math.max(0, Math.floor(M.resteVar / M.daysLeft)))} par jour.</p>`
      : `<h1>${euros0(planVar)} par mois pour vivre</h1><p class="lede">C'est le plan. Tes vraies dépenses s'afficheront ici dès que la synchro Actual tournera.</p>`;
    const summary = `<dl class="kv">
      <div><dt>${esc(B.revenu.nom)}</dt><dd>${euros(B.revenu.montant)}</dd></div>
      <div><dt>Budgété</dt><dd>${budgetedTotal != null ? eur(budgetedTotal) : euros(planTotal)}</dd></div>
      <div><dt>${M.month ? 'À budgétiser' : 'Marge'}</dt><dd>${M.month ? eur(M.month.toBudget) : euros(B.revenu.montant - planTotal)}</dd></div>
    </dl>`;
    const groupsHtml = visible.map(g => groupBlock(g, M)).join('');
    const uncat = S.snap ? S.snap.uncategorized || 0 : 0;
    const actual = B.actualUrl ? `<a class="btn" href="${esc(B.actualUrl)}" target="_blank" rel="noopener">Ouvrir Actual</a>` : '';
    let tbNote = '';
    if (M.month && M.month.toBudget < 0) {
      tbNote = M.bourse
        ? '<p class="note warn"><b>À budgétiser négatif</b> · Tu as réparti plus que ce que tu as. Baisse une catégorie dans Actual.</p>'
        : `<p class="note"><b>À budgétiser négatif, c'est normal</b> · Le budget de ${mName} compte déjà sur la bourse, pas encore arrivée. Il remonte dès qu'elle tombe.</p>`;
    } else if (M.month && M.month.toBudget > 0) {
      tbNote = `<p class="note"><b>${eur(M.month.toBudget)} pas encore répartis</b> · Mets-les dans Épargne dans Actual : c'est ton coussin de sécurité.</p>`;
    }
    return `<section><p class="eyebrow">Budget de ${mName}</p>${head}${summary}${tbNote}
        <div class="btn-row">${actual}${uncat ? `<span class="chip warn">${uncat} transaction${uncat > 1 ? 's' : ''} à classer</span>` : ''}</div>
        ${freshness()}</section>
      <section aria-labelledby="w-h"><h2 id="w-h">La règle de la semaine</h2><p class="note">${esc(B.semaine.regle)}</p></section>
      ${subsBlock()}
      ${groupsHtml}
      ${avantBlock(B)}
      ${fixedBlock(M)}
      ${recentBlock(M, iso)}`;
  }

  function groupBlock(g, M) {
    const rows = g.categories.map(c => catRow(c, M));
    const plan = sum(g.categories.map(c => planBudget(M.B, c.nom, M.ym)));
    let right = euros(plan);
    if (M.month) {
      const spent = -sum(g.categories.map(c => (M.catsByName.get(c.nom) || {}).spent || 0));
      const budgeted = sum(g.categories.map(c => (M.catsByName.get(c.nom) || {}).budgeted || 0));
      right = `${eur(spent)} / ${eur(budgeted)}`;
    }
    return `<section aria-label="${esc(g.nom)}"><div class="group-head"><h2>${esc(g.nom)}</h2><span>${right}</span></div><div>${rows.join('')}</div></section>`;
  }

  function catRow(c, M) {
    const a = M.month ? M.catsByName.get(c.nom) : null;
    if (!a) {
      return `<div class="cat"><div class="cat-top"><b class="grow">${esc(c.nom)}</b><span class="left">${euros(planBudget(M.B, c.nom, M.ym))}</span></div>${c.note ? `<p class="sub">${esc(c.note)}</p>` : ''}</div>`;
    }
    const spent = -a.spent;
    const budget = a.budgeted;
    const pend = pendingList().filter(o => o.op === 'set-budget' && o.category === c.nom).pop();
    const editing = S.form && S.form.type === 'cat' && S.form.name === c.nom;
    const editUi = editing
      ? `<form class="inline-form" data-form="cat" data-name="${esc(c.nom)}"><div class="field"><label for="cf-amount">Par mois, à partir de ce mois (€)</label><input class="input" id="cf-amount" name="amount" type="text" inputmode="decimal" autocomplete="off" required value="${budget / 100}"></div><button class="btn primary" type="submit">OK</button><button class="btn ghost" type="button" data-act="form-cancel">Annuler</button></form><p class="small muted">Appliqué à ce mois et aux 3 suivants.</p>`
      : '';
    const state = a.balance < 0 ? 'bad' : budget > 0 && spent / budget >= 0.85 ? 'warn' : 'ok';
    const width = budget > 0 ? pct(spent, budget) : spent > 0 ? 100 : 0;
    const left = a.balance < 0 ? `<span class="chip bad">−${eur(-a.balance)}</span>` : `<span class="chip ${state}">reste ${eur(a.balance)}</span>`;
    const pendChip = pend ? ` <span class="chip accent">→ ${euros(pend.amount)} en cours</span>` : '';
    return `<div class="cat"><div class="cat-top"><b class="grow">${esc(c.nom)}${pendChip}</b><span class="figures">${eur(spent)} / ${eur(budget)}</span>${left}</div>
      <div class="meter ${state}"><span style="width:${width}%"></span></div>
      <div class="cat-foot">${c.note ? `<p class="sub">${esc(c.note)}</p>` : '<span></span>'}${editing ? '' : `<button type="button" class="btn ghost small-btn" data-cat-edit="${esc(c.nom)}" aria-label="Modifier le budget ${esc(c.nom)}">Modifier</button>`}</div>${editUi}</div>`;
  }

  function avantBlock(B) {
    const a = B.avant;
    if (!a) return '';
    const rows = a.lignes.map(l => `<span class="name">${esc(l.nom)}<small>${esc(l.detail || '')}</small></span><span class="v num">${euros0(l.mois)}</span><span class="v num ${l.plan < l.mois ? 'down' : ''}">${euros0(l.plan)}</span>`).join('');
    return `<section aria-labelledby="a-h"><h2 id="a-h">Avant, et avec le plan</h2><p class="small muted">${esc(a.periode)}</p>
      <div class="compare"><span class="h">Poste</span><span class="h v">Avant</span><span class="h v">Plan</span>${rows}</div>
      <p class="note">${esc(a.resume)}</p></section>`;
  }

  function fixedBlock(M) {
    if (!S.snap) return '';
    const fixed = new Set(M.groups.filter(g => !g.variable && !g.masque).flatMap(g => g.categories.map(c => c.nom)));
    const rows = new Map();
    M.tx.filter(t => t.amount < 0 && fixed.has(t.category)).forEach(t => {
      const k = String(t.payee || '').toLowerCase();
      const cur = rows.get(k);
      if (!cur) rows.set(k, Object.assign({}, t, { n: 1 }));
      else if (t.date > cur.date) rows.set(k, Object.assign({}, t, { n: cur.n + 1 }));
      else cur.n += 1;
    });
    const list = [...rows.values()].sort((a, b) => a.category.localeCompare(b.category, 'fr') || a.amount - b.amount);
    if (!list.length) return '';
    return `<section aria-labelledby="f-h"><h2 id="f-h">Vu sur tes comptes</h2><p class="small muted">Paiements fixes des 62 derniers jours, avec le dernier montant. Un abonnement oublié se repère ici.</p>
      <ul class="list">${list.map(t => `<li><div class="grow"><div class="title">${esc(t.payee)}</div><div class="meta"><span class="chip">${esc(t.category)}</span> · ${esc(shortDate(t.date))} · ${t.n} fois</div></div><div class="amount">${eur(t.amount)}</div></li>`).join('')}</ul></section>`;
  }

  function recentBlock(M, iso) {
    if (!S.snap) return '';
    const from = addDays(iso, -6);
    const tx = M.tx.filter(t => t.date >= from && t.date <= iso && t.amount !== 0 && !M.hidden.has(t.category));
    const spent = -sum(tx.filter(M.isSpend).map(t => t.amount));
    if (!tx.length) return '<section><h2>7 derniers jours</h2><p class="muted">Aucune transaction.</p></section>';
    const days = [...new Set(tx.map(t => t.date))].sort().reverse();
    return `<section aria-labelledby="t-h"><div class="group-head"><h2 id="t-h">7 derniers jours</h2><span>${eur(spent)}</span></div>
      ${days.map(d => {
        const dt = tx.filter(t => t.date === d);
        return `<div class="dayhead">${esc(longDate(d))} · ${eur(-sum(dt.filter(M.isSpend).map(t => t.amount)))}</div><ul class="list">${dt.map(txRow).join('')}</ul>`;
      }).join('')}</section>`;
  }

  // ---------- REPAS ----------
  function viewRepas() {
    const r = S.plan.repas;
    const iso = S.today;
    const m = mealsOf(iso);
    const before = prog(iso).before;
    const current = before ? 'A' : m.tM;
    const type = S.repasType || current;
    const nc = nextCourse(iso);
    const seg = ['A', 'B'].map(t => `<button type="button" data-rtype="${t}" aria-pressed="${t === type}">Semaine ${t}${t === current ? (before ? ' · la 1re' : ' · en cours') : ''}</button>`).join('');
    return `<section><p class="eyebrow">${esc(r.etiquette || 'Plan repas')}</p>
        <h1>${NUM.format(r.objectifs.kcal)}&nbsp;kcal, ${r.objectifs.proteines}&nbsp;g de protéines</h1>
        <p class="lede">${esc(r.objectifs.base)}</p></section>
      ${needsPont(iso, prog(iso)) ? pontBlock(iso) : ''}
      ${nc ? courseBlock(nc, iso) : ''}
      <section aria-labelledby="pl-h"><div class="group-head"><h2 id="pl-h">La semaine type</h2></div><div class="seg" role="group" aria-label="Semaine">${seg}</div>${planningBlock(type)}</section>
      ${recipesBlock(type)}
      ${listsBlock(type)}
      <section aria-labelledby="rg-h"><h2 id="rg-h">Les règles</h2><div class="stack">${r.regles.map((x, i) => `<details data-k="rg${i}"><summary><span class="sum-main"><b>${esc(x.titre)}</b></span></summary><div class="body"><p>${esc(x.texte)}</p></div></details>`).join('')}</div>
        <p class="note"><b>Resto U</b> · ${esc(r.restoU.regle)} ${esc(r.restoU.planB)}</p>
        <p class="note"><b>Réglage</b> · ${esc(r.objectifs.ajustement)}</p></section>`;
  }

  function courseBlock(nc, iso) {
    const r = S.plan.repas;
    const st = store.get('courses:' + nc.date, {});
    const items = nc.list.articles;
    const when = nc.k === 0 ? 'ce soir' : nc.k === 1 ? 'demain soir' : `${JOURS[weekday(nc.date)]} soir`;
    const total = sum(items.map(a => a.prix));
    const left = sum(items.filter((a, i) => !st[i]).map(a => a.prix));
    const withStock = prog(iso).before && r.courses.stock;
    const stockSt = store.get('courses:stock', {});
    const stock = withStock ? `<h3>${esc(r.courses.stock.titre)}</h3><ul class="checks">${r.courses.stock.articles.map((a, i) => checkItem(`st-${i}`, `data-course="stock" data-i="${i}"`, stockSt[i], a.nom, '', `<span class="price">${euros(a.prix)}</span>`)).join('')}</ul>` : '';
    return `<section class="card" aria-labelledby="co-h">
      <p class="hero-label" id="co-h">Prochaine course · ${esc(when)} · semaine ${nc.type}</p>
      <h2>${esc(nc.list.titre)}</h2>
      <p class="small muted num">≈ ${euros(total)}${left < total ? ` · reste ${euros(left)} à prendre` : ''}</p>
      ${needsPont(iso, prog(iso)) ? '<p class="note warn"><b>Après la bourse</b> · En attendant, seulement le kit pont.</p>' : ''}
      <ul class="checks">${items.map((a, i) => checkItem(`c-${nc.date}-${i}`, `data-course="${nc.date}" data-i="${i}"`, st[i], a.nom, a.pour ? `pour ${a.pour}` : '', `<span class="price">${euros(a.prix)}</span>`)).join('')}</ul>
      ${stock}
    </section>`;
  }

  function planningBlock(type) {
    const r = S.plan.repas;
    const other = type === 'A' ? 'B' : 'A';
    const name = (slot, wd) => {
      if (slot === 'ru') return 'Resto U';
      if (slot.batch) {
        const t = slot.batch === 'dimanche' && wd === 0 ? other : type;
        return `${r.recettes[r.semaines[t][slot.batch]].nom} (${slot.portion})`;
      }
      return r.recettes[slot.recette].nom;
    };
    const rows = [1, 2, 3, 4, 5, 6, 0].map(wd => {
      const d = r.jours[String(wd)];
      return `<li><div class="grow"><div class="title">${JC[wd]}</div><div class="meta">Midi : ${esc(name(d.midi, wd))}</div><div class="meta">Soir : ${esc(name(d.diner, wd))}</div>${d.soir ? `<div class="meta"><b>→ ${esc(d.soir)}</b></div>` : ''}</div></li>`;
    }).join('');
    return `<ul class="list">${rows}</ul><p class="small muted">Petit-déj et collation identiques tous les jours. Le batch du dimanche prépare la semaine suivante.</p>`;
  }

  function recipeCard(id, rec, tag) {
    return `<details data-k="rec-${esc(id)}"><summary><span class="sum-main"><b>${esc(rec.nom)}</b><span>${esc(tag)} · ${esc(rec.temps)} · ${rec.portions} portion${rec.portions > 1 ? 's' : ''} · ${rec.kcal} kcal · ${rec.prot} g · ${euros(rec.cout)} la portion</span></span></summary>
      <div class="body"><h3>Ingrédients</h3><ul>${rec.ingredients.map(i => `<li>${esc(i)}</li>`).join('')}</ul>
      <h3>Étapes</h3><ol>${rec.etapes.map(e => `<li>${esc(e)}</li>`).join('')}</ol>
      ${rec.conservation ? `<p class="small muted">Conservation : ${esc(rec.conservation)}</p>` : ''}
      ${rec.astuce ? `<p class="note">${esc(rec.astuce)}</p>` : ''}</div></details>`;
  }

  function recipesBlock(type) {
    const r = S.plan.repas;
    const R = r.recettes;
    const w = r.semaines[type];
    const cards = [
      [w.dimanche, 'Batch dimanche : dîner, puis boîtes lundi-mercredi'],
      [w.mercredi, 'Batch mercredi : dîner, puis boîtes jeudi-samedi'],
      ['pates-thon', 'Express vendredi soir'],
      ['sushi-bowl', 'Express samedi soir'],
      ['shakshuka', 'Brunch du dimanche'],
      ...(r.jokers || (r.joker ? [r.joker] : [])).map(id => [id, 'Joker']),
      ['bol-avoine', 'Tous les matins'],
      ['collation', 'Tous les jours'],
    ].filter(([id]) => R[id]);
    return `<section aria-labelledby="rc-h"><h2 id="rc-h">Recettes de la semaine ${type}</h2><div class="stack">${cards.map(([id, tag]) => recipeCard(id, R[id], tag)).join('')}</div></section>`;
  }

  function listsBlock(type) {
    const r = S.plan.repas;
    const lists = (r.courses[type] || []).concat(r.courses.stock ? [r.courses.stock] : []);
    return `<section aria-labelledby="ls-h"><h2 id="ls-h">Toutes les listes · semaine ${type}</h2><div class="stack">${lists.map((l, i) => {
      const total = sum(l.articles.map(a => a.prix));
      return `<details data-k="ls-${type}-${i}"><summary><span class="sum-main"><b>${esc(l.titre)}</b><span>${l.articles.length} articles · ≈ ${euros(total)}</span></span></summary>
        <div class="body"><ul class="list">${l.articles.map(a => `<li><div class="grow"><div class="title">${esc(a.nom)}</div>${a.pour ? `<div class="meta">pour ${esc(a.pour)}</div>` : ''}</div><div class="amount">${euros(a.prix)}</div></li>`).join('')}</ul></div></details>`;
    }).join('')}</div><p class="small muted">Prix estimés, à recaler avec tes tickets. La course 1 de la semaine A contient aussi les basiques pour deux semaines.</p></section>`;
  }

  // ---------- SPORT ----------
  function viewSport() {
    const sp = S.plan.sport;
    const iso = S.sportDay || (prog(S.today).before ? sp.debut : S.today); // avant J1 : on montre la 1re séance
    const s = sessionOf(iso);
    const p = s.p;
    const mon = mondayOf(iso);
    const strip = [0, 1, 2, 3, 4, 5, 6].map(k => {
      const d = addDays(mon, k);
      return `<button type="button" data-sday="${d}" aria-pressed="${d === iso}" class="${d === S.today ? 'today' : ''}" aria-label="${esc(longDate(d))}">${JC[weekday(d)]}<b>${toDate(d).getUTCDate()}</b></button>`;
    }).join('');
    const eyebrow = p.before ? `Départ ${esc(longDate(sp.debut))}` : `Semaine ${p.week} · phase ${p.phase.num} · ${esc(p.phase.nom.toLowerCase())}`;
    const dayLabel = iso === S.today ? '' : `<p class="small muted">Séance du ${esc(longDate(iso))}${p.before ? ', en phase 1' : ''}</p>`;
    const isRest = s.id === 'repos';
    const warm = s.blocs.length && s.id !== 'cardio-2'
      ? `<details data-k="warm"><summary><span class="sets">5 min</span><span class="sum-main"><b>Échauffement</b><span>Toujours, même pressé</span></span></summary><div class="body"><ul>${sp.echauffement.map(e => `<li>${esc(e)}</li>`).join('')}</ul></div></details>`
      : '';
    const blocks = s.blocs.map((b, i) => exerciseCard(b, i, s)).join('');
    const st = store.get('jour:' + iso, {});
    return `<section><p class="eyebrow">${eyebrow}</p><h1>${esc(s.nom)}</h1>${dayLabel}
        <p class="lede">${isRest ? '' : `${s.duree} min · ${esc(p.phase.effort)} Repos ${esc(p.phase.repos)} entre les séries.`}${p.deload ? ` ${esc(sp.allegee)}` : ''}</p>
        <div class="weekstrip" role="group" aria-label="Jours de la semaine">${strip}</div></section>
      ${s.test ? '<p class="note"><b>Jour de test</b> · Note tes résultats dans l\'onglet Suivi, puis fais la séance.</p>' : ''}
      <section aria-label="Exercices">
        ${s.circuit ? `<p class="note"><b>Circuit</b> · ${s.circuit.tours} tours, enchaîne les exercices sans pause, ${esc(s.circuit.repos)} de repos entre les tours.</p>` : ''}
        <div class="stack">${warm}${blocks}</div>
        ${s.fin ? `<p class="note">${esc(s.fin)}</p>` : ''}
        ${isRest ? '' : `<div class="btn-row">${[45, 60, 90].map(sec => `<button type="button" class="btn" data-timer="${sec}">Repos ${sec} s</button>`).join('')}</div>`}
        <ul class="checks">${checkItem(`seance-${iso}`, `data-day="${iso}" data-key="seance"`, st.seance, isRest ? 'Repos actif fait' : 'Séance faite', '')}</ul>
      </section>
      ${programmeBlock(p)}`;
  }

  function exerciseCard(b, i, s) {
    const sets = s.circuit || b.series === 1 ? b.reps : `${b.series} × ${b.reps}`;
    return `<details data-k="ex-${s.id}-${i}"><summary><span class="sets">${esc(sets)}</span><span class="sum-main"><b>${esc(b.ex.nom)}</b><span>${esc(b.variante)}</span></span></summary>
      <div class="body">${b.ex.muscles ? `<p class="small muted">${esc(b.ex.muscles)}</p>` : ''}
        <ul>${(b.ex.consignes || []).map(c => `<li>${esc(c)}</li>`).join('')}</ul>
        <p class="small"><b>Trop dur :</b> ${esc(b.ex.facile || '—')}<br><b>Trop facile :</b> ${esc(b.ex.dur || '—')}</p></div></details>`;
  }

  function programmeBlock(p) {
    const sp = S.plan.sport;
    const week = [1, 2, 3, 4, 5, 6, 0].map(wd => `<li><div class="grow"><div class="title">${JOURS[wd].replace(/^./, c => c.toUpperCase())}</div><div class="meta">${esc(sp.seances[sp.semaine[String(wd)]].nom)}</div></div></li>`).join('');
    const phases = sp.phases.map(ph => `<li><div class="grow"><div class="title">Phase ${ph.num} · ${esc(ph.nom)}</div><div class="meta">J${ph.de} à J${ph.a} · ${ph.series} séries · repos ${esc(ph.repos)}</div><div class="meta">${esc(ph.effort)}</div></div>${ph.num === p.phase.num && !p.before ? '<span class="chip accent">en cours</span>' : ''}</li>`).join('');
    const pas = sp.pas.map(x => `J${x.de}-J${x.a} : ${NUM.format(x.objectif)}`).join(' · ');
    return `<section aria-labelledby="pg-h"><h2 id="pg-h">Le programme</h2><div class="stack">
      <details data-k="pg-sem"><summary><span class="sum-main"><b>Semaine type</b><span>6 séances, 1 repos actif</span></span></summary><div class="body"><ul class="list">${week}</ul></div></details>
      <details data-k="pg-ph"><summary><span class="sum-main"><b>Les 3 phases</b><span>Semaines allégées : ${esc(sp.phases.filter(x => x.allegee).map(x => `J${x.allegee[0]}-J${x.allegee[1]}`).join(', '))}</span></span></summary><div class="body"><ul class="list">${phases}</ul><p class="small muted">${esc(sp.allegee)}</p></div></details>
      <details data-k="pg-pas"><summary><span class="sum-main"><b>Pas par jour</b><span>${esc(pas)}</span></span></summary><div class="body"><p>La marche brûle du gras sans te fatiguer pour les séances. Marcher plutôt que prendre le tram fait les deux d'un coup.</p></div></details>
      <details data-k="pg-mat"><summary><span class="sum-main"><b>Matériel</b><span>0 € pour démarrer</span></span></summary><div class="body"><p>${esc(sp.materiel.base)}</p><p class="small muted">${esc(sp.materiel.option)}</p></div></details>
      <details data-k="pg-reg"><summary><span class="sum-main"><b>Les règles</b><span>Sécurité, sommeil, progression</span></span></summary><div class="body"><ul>${sp.regles.map(x => `<li>${esc(x)}</li>`).join('')}</ul></div></details>
      <details data-k="pg-att"><summary><span class="sum-main"><b>À quoi t'attendre</b><span>Les vrais chiffres</span></span></summary><div class="body"><ul>${sp.attentes.map(x => `<li>${esc(x)}</li>`).join('')}</ul></div></details>
    </div></section>`;
  }

  // ---------- SUIVI ----------
  function viewSuivi() {
    const iso = S.today;
    const sp = S.plan.sport;
    const poids = store.get('poids', {});
    const entries = Object.entries(poids).filter(([, v]) => typeof v === 'number').sort(([a], [b]) => (a < b ? -1 : 1));
    const weeks = new Map();
    entries.forEach(([d, v]) => { const m = mondayOf(d); if (!weeks.has(m)) weeks.set(m, []); weeks.get(m).push(v); });
    const wavg = [...weeks.entries()].map(([m, vs]) => ({ m, avg: sum(vs) / vs.length, n: vs.length }));
    const last = wavg[wavg.length - 1];
    const prev = wavg[wavg.length - 2];
    const first = wavg[0];
    const fmtKg = v => `${NUM.format(Math.round(v * 10) / 10)} kg`;
    const kv = entries.length ? `<dl class="kv">
        <div><dt>Moyenne semaine</dt><dd>${fmtKg(last.avg)}</dd></div>
        <div><dt>vs semaine d'avant</dt><dd>${prev ? `${last.avg - prev.avg <= 0 ? '−' : '+'}${NUM.format(Math.abs(Math.round((last.avg - prev.avg) * 10) / 10))} kg` : '—'}</dd></div>
        <div><dt>Depuis le début</dt><dd>${first && first !== last ? `${last.avg - first.avg <= 0 ? '−' : '+'}${NUM.format(Math.abs(Math.round((last.avg - first.avg) * 10) / 10))} kg` : '—'}</dd></div>
      </dl>` : '';
    const tests = store.get('tests', {});
    const cols = sp.tests.jours;
    const table = `<div class="scroll-x"><table class="tests"><thead><tr><th>Test</th>${cols.map(j => `<th>J${j}</th>`).join('')}</tr></thead><tbody>
      ${sp.tests.liste.map(t => `<tr><td>${esc(t.nom)} <span class="muted small">(${esc(t.unite)})</span></td>${cols.map(j => `<td><input id="t-${t.id}-${j}" inputmode="decimal" type="text" autocomplete="off" data-test="${t.id}" data-j="${j}" value="${tests[t.id] && tests[t.id][j] != null ? tests[t.id][j] : ''}" aria-label="${esc(t.nom)} J${j}"></td>`).join('')}</tr>`).join('')}
      </tbody></table></div>`;
    const todayVal = poids[iso];
    return `<section><p class="eyebrow">Suivi</p><h1>Poids, tests et mesures</h1>
        <p class="lede">Pèse-toi chaque matin, après les toilettes, avant de boire. Ne regarde que la moyenne de la semaine : un jour isolé ne veut rien dire.</p></section>
      <section aria-labelledby="p-h"><h2 id="p-h">Poids</h2>
        <form class="inline-form" data-form="poids"><div class="field"><label for="poids-input">Ce matin (kg)</label><input class="input" id="poids-input" inputmode="decimal" type="text" autocomplete="off" value="${todayVal != null ? todayVal : ''}" placeholder="kg"></div><button class="btn primary" type="submit">Noter</button></form>
        ${kv}${weightChart(entries)}
        ${entries.length ? `<details data-k="poids-hist"><summary><span class="sum-main"><b>Historique</b><span>${entries.length} pesée${entries.length > 1 ? 's' : ''}</span></span></summary><div class="body"><ul class="list">${entries.slice().reverse().slice(0, 60).map(([d, v]) => `<li><div class="grow">${esc(longDate(d))}</div><div class="amount">${fmtKg(v)}</div><button type="button" class="btn ghost" data-del-poids="${d}" aria-label="Supprimer la pesée du ${esc(longDate(d))}">Suppr.</button></li>`).join('')}</ul></div></details>` : ''}
      </section>
      <section aria-labelledby="ts-h"><h2 id="ts-h">Tests et mesures</h2><p class="small muted">Aux jours J${cols.join(', J')}. Photos : ${esc(sp.tests.photos.replace(/^./, c => c.toLowerCase()))}</p>${table}</section>
      ${ghBlock()}
      <section aria-labelledby="sv-h"><h2 id="sv-h">Sauvegarde</h2>
        <p class="small muted">Tes pesées, tests et cases cochées restent sur cet appareil. Copie la sauvegarde de temps en temps dans tes notes.</p>
        <div class="btn-row"><button class="btn" type="button" data-act="export">Copier la sauvegarde</button><button class="btn" type="button" data-act="import">Restaurer depuis le texte</button></div>
        <label class="small" for="backup-text">Texte de sauvegarde</label>
        <textarea class="input" id="backup-text" placeholder="La sauvegarde apparaît ici. Pour restaurer, colle-la puis touche Restaurer."></textarea>
        <p class="small muted" id="backup-msg" role="status"></p>
        ${window.__CAP90__ ? '' : '<div class="btn-row"><button class="btn ghost" type="button" data-act="lock">Verrouiller cet appareil</button></div>'}
      </section>`;
  }

  function weightChart(entries) {
    if (entries.length < 2) return '<p class="small muted">Le graphique apparaît à partir de 2 pesées.</p>';
    const W = 320, H = 160, L = 38, R = 12, T = 12, Bm = 26;
    const d0 = entries[0][0];
    const d1 = entries[entries.length - 1][0];
    const span = Math.max(1, diffDays(d1, d0));
    const vals = entries.map(e => e[1]);
    let lo = Math.floor(Math.min(...vals) - 0.5);
    let hi = Math.ceil(Math.max(...vals) + 0.5);
    if (hi - lo < 2) hi = lo + 2;
    const x = d => L + (diffDays(d, d0) / span) * (W - L - R);
    const y = v => T + ((hi - v) / (hi - lo)) * (H - T - Bm);
    const avg = entries.map(([d]) => {
      const from = addDays(d, -6);
      const win = entries.filter(([dd]) => dd >= from && dd <= d).map(e => e[1]);
      return [d, sum(win) / win.length];
    });
    const ticks = [lo, (lo + hi) / 2, hi];
    const grid = ticks.map(v => `<line class="grid" x1="${L}" x2="${W - R}" y1="${y(v).toFixed(1)}" y2="${y(v).toFixed(1)}"/><text x="${L - 6}" y="${(y(v) + 4).toFixed(1)}" text-anchor="end">${NUM.format(v)}</text>`).join('');
    const dots = entries.map(([d, v]) => `<circle class="raw" cx="${x(d).toFixed(1)}" cy="${y(v).toFixed(1)}" r="2.2"/>`).join('');
    const path = avg.map(([d, v], i) => `${i ? 'L' : 'M'}${x(d).toFixed(1)},${y(v).toFixed(1)}`).join(' ');
    const [ld, lv] = avg[avg.length - 1];
    return `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Poids quotidien et moyenne sur 7 jours">${grid}${dots}<path class="avg" d="${path}"/><circle class="end" cx="${x(ld).toFixed(1)}" cy="${y(lv).toFixed(1)}" r="4"/>
      <text x="${L}" y="${H - 6}">${esc(shortDate(d0))}</text><text x="${W - R}" y="${H - 6}" text-anchor="end">${esc(shortDate(d1))}</text></svg>
      <p class="small muted">Points : pesées du jour. Ligne : moyenne sur 7 jours.</p>`;
  }

  // ---------- minuteur de repos ----------
  function startTimer(sec) {
    stopTimer();
    try { if (!S.audio) S.audio = new (window.AudioContext || window.webkitAudioContext)(); } catch (e) { S.audio = null; }
    const el = document.getElementById('timer');
    el.innerHTML = '<div class="timer-inner"><span class="grow small">Repos</span><b class="num" id="timer-left"></b><button type="button" data-timer-stop>Stop</button></div>';
    el.hidden = false;
    const end = Date.now() + sec * 1000;
    const out = document.getElementById('timer-left');
    const tick = () => {
      const left = Math.max(0, Math.ceil((end - Date.now()) / 1000));
      out.textContent = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}`;
      if (left === 0) {
        stopTimer();
        beep();
        try { if (navigator.vibrate) navigator.vibrate([200, 100, 200]); } catch (e) { /* pas de vibreur */ }
      }
    };
    tick();
    S.timer = setInterval(tick, 250);
  }

  function stopTimer() {
    if (S.timer) clearInterval(S.timer);
    S.timer = null;
    const el = document.getElementById('timer');
    if (el) { el.hidden = true; el.innerHTML = ''; }
  }

  function beep() {
    const a = S.audio;
    if (!a) return;
    try {
      const o = a.createOscillator();
      const g = a.createGain();
      o.frequency.value = 880;
      g.gain.setValueAtTime(0.0001, a.currentTime);
      g.gain.exponentialRampToValueAtTime(0.3, a.currentTime + 0.02);
      g.gain.exponentialRampToValueAtTime(0.0001, a.currentTime + 0.5);
      o.connect(g);
      g.connect(a.destination);
      o.start();
      o.stop(a.currentTime + 0.55);
    } catch (e) { /* pas de son */ }
  }

  // ---------- écrans sans contenu ----------
  function renderLock(err) {
    document.getElementById('view').innerHTML = `<section class="center-screen">
      <p class="eyebrow">Cap 90</p><h1>Déverrouille ton plan</h1>
      <p class="lede">Tout est chiffré. Tape la phrase secrète choisie quand tu as connecté Actual.</p>
      <form class="lock-form" data-form="lock">
        <div class="field"><label for="pass">Phrase secrète</label><input class="input" id="pass" type="password" autocomplete="current-password" required></div>
        <label class="check"><input type="checkbox" id="remember" checked><span class="grow"><span class="label">Se souvenir sur cet appareil</span></span></label>
        <button class="btn primary" type="submit" id="unlock-btn">Déverrouiller</button>
        ${err ? `<p class="error" role="alert">${esc(err)}</p>` : ''}
      </form></section>`;
  }

  function renderEmpty() {
    document.getElementById('view').innerHTML = `<section class="center-screen"><p class="eyebrow">Cap 90</p><h1>Pas encore de données</h1>
      <p class="lede">Le site est en ligne, mais la première synchronisation n'a pas encore tourné. Lance le script de connexion sur ton Mac, puis reviens ici.</p></section>`;
  }

  function start(payload) {
    S.plan = payload.plan || null;
    S.snap = payload.snapshot || null;
    if (!S.plan || !S.plan.budget || !S.plan.repas || !S.plan.sport) {
      document.getElementById('view').innerHTML = '<section class="center-screen"><h1>Plan incomplet</h1><p class="lede">Le fichier reçu ne contient pas le budget, les repas et le sport. Relance la synchro.</p></section>';
      return;
    }
    S.loadedAt = Date.now();
    render();
    if (pendingOps().length) schedulePendingRefresh();
  }

  // ---------- événements ----------
  document.addEventListener('change', e => {
    const t = e.target;
    if (t.matches('[data-day][data-key]')) {
      const k = 'jour:' + t.dataset.day;
      const st = store.get(k, {});
      st[t.dataset.key] = t.checked;
      store.set(k, st);
      if (S.view === 'aujourdhui') render();
    } else if (t.matches('[data-mer]')) {
      const st = store.get('miseEnRoute', {});
      st[t.dataset.mer] = t.checked;
      store.set('miseEnRoute', st);
    } else if (t.matches('[data-lev]')) {
      const st = store.get('leviers', {});
      st[t.dataset.lev] = t.checked;
      store.set('leviers', st);
      render();
    } else if (t.matches('[data-course]')) {
      const k = 'courses:' + t.dataset.course;
      const st = store.get(k, {});
      st[t.dataset.i] = t.checked;
      store.set(k, st);
    } else if (t.matches('[data-test]')) {
      const st = store.get('tests', {});
      st[t.dataset.test] = st[t.dataset.test] || {};
      const v = parseFloat(String(t.value).replace(',', '.'));
      if (Number.isFinite(v)) st[t.dataset.test][t.dataset.j] = v;
      else delete st[t.dataset.test][t.dataset.j];
      store.set('tests', st);
    }
  });

  document.addEventListener('toggle', e => {
    const d = e.target;
    if (d.tagName === 'DETAILS' && d.dataset.k) {
      if (d.open) S.open.add(d.dataset.k);
      else S.open.delete(d.dataset.k);
    }
  }, true);

  document.addEventListener('click', e => {
    const b = e.target.closest('button');
    if (!b) return;
    if (b.dataset.rtype) { S.repasType = b.dataset.rtype; render(); }
    else if (b.dataset.sday) { S.sportDay = b.dataset.sday; render(); }
    else if (b.dataset.timer) startTimer(Number(b.dataset.timer));
    else if ('timerStop' in b.dataset) stopTimer();
    else if (b.dataset.delPoids) {
      const st = store.get('poids', {});
      delete st[b.dataset.delPoids];
      store.set('poids', st);
      render();
    } else if (b.dataset.subEdit) { S.form = { type: 'sub', id: b.dataset.subEdit }; S.focusForm = true; render(); }
    else if (b.dataset.subDel) { S.form = { type: 'del', id: b.dataset.subDel }; render(); }
    else if (b.dataset.delConfirm) {
      const sub = ((S.snap && S.snap.subscriptions) || []).find(x => x.id === b.dataset.delConfirm);
      b.disabled = true;
      sendOps([{ op: 'delete-sub', id: b.dataset.delConfirm, adjustBudget: true }], `Abonnement « ${sub ? sub.name : ''} » supprimé`).then(ok => { if (ok) S.form = null; render(); });
    }
    else if (b.dataset.catEdit) { S.form = { type: 'cat', name: b.dataset.catEdit }; S.focusForm = true; render(); }
    else if (b.dataset.act === 'sub-new') { S.form = { type: 'sub' }; S.focusForm = true; render(); }
    else if (b.dataset.act === 'tx-new') { S.form = { type: 'tx' }; S.focusForm = true; render(); }
    else if (b.dataset.act === 'form-cancel') { S.form = null; render(); }
    else if (b.dataset.act === 'refresh') refreshData(false);
    else if (b.dataset.act === 'banksync') bankSync(b).then(() => render());
    else if (b.dataset.act === 'gh-forget') { store.del('gh'); toast('Jeton oublié sur cet appareil.', 'ok'); render(); }
    else if (b.dataset.act === 'gh-test') { b.disabled = true; testConnection(); }
    else if (b.dataset.act === 'export') exportBackup();
    else if (b.dataset.act === 'import') importBackup();
    else if (b.dataset.act === 'lock') { store.del('pass'); location.reload(); }
  });

  document.addEventListener('submit', async e => {
    const f = e.target;
    e.preventDefault();
    if (f.dataset.form === 'poids') {
      const v = parseFloat(String(document.getElementById('poids-input').value).replace(',', '.'));
      if (!Number.isFinite(v) || v < 40 || v > 250) return;
      const st = store.get('poids', {});
      st[S.today] = Math.round(v * 10) / 10;
      store.set('poids', st);
      render();
    } else if (['sub', 'cat', 'tx'].includes(f.dataset.form) && !lockSubmit(f)) {
      return;
    } else if (f.dataset.form === 'sub') {
      await submitSub(f);
      unlockSubmit(f);
    } else if (f.dataset.form === 'cat') {
      const amount = Math.round(parseFloat(String(new FormData(f).get('amount')).replace(',', '.')) * 100) / 100;
      if (!Number.isFinite(amount) || amount < 0 || amount > 5000) { toast('Montant entre 0 et 5 000 €.', 'warn'); unlockSubmit(f); return; }
      const ok = await sendOps([{ op: 'set-budget', category: f.dataset.name, amount, months: 4 }], `Budget ${f.dataset.name} → ${euros(amount)}`);
      if (ok) { S.form = null; render(); } else unlockSubmit(f);
    } else if (f.dataset.form === 'tx') {
      const fd = new FormData(f);
      const amount = Math.round(parseFloat(String(fd.get('amount')).replace(',', '.')) * 100) / 100;
      if (!Number.isFinite(amount) || amount <= 0 || amount > 2000) { toast('Montant entre 0,01 et 2 000 €.', 'warn'); unlockSubmit(f); return; }
      const op = { op: 'add-tx', account: String(fd.get('account')), date: String(fd.get('date') || S.today), amount: -amount, category: String(fd.get('category')) };
      const payee = String(fd.get('payee') || '').trim();
      if (payee) op.payee = payee.slice(0, 60);
      const ok = await sendOps([op], `Dépense ${euros(amount)} (${op.category})`);
      if (ok) { S.form = null; render(); } else unlockSubmit(f);
    } else if (f.dataset.form === 'gh') {
      const token = document.getElementById('gh-token').value.trim();
      if (!token) return;
      store.set('gh', token);
      try {
        await GH.call(`/repos/${GH.repo()}/actions/workflows/edit.yml`);
      } catch (e) {
        store.del('gh'); // illisible : on ne garde pas un jeton qui ne mène nulle part
        toast(ghError(e), 'bad');
        render();
        return;
      }
      // Lecture OK : on garde le jeton (ses permissions se corrigent sur GitHub sans le recréer), et on teste l'écriture.
      await testConnection();
    } else if (f.dataset.form === 'lock') {
      const pass = document.getElementById('pass').value;
      const remember = document.getElementById('remember').checked;
      const btn = document.getElementById('unlock-btn');
      btn.disabled = true;
      btn.textContent = 'Déchiffrement…';
      try {
        const payload = await decrypt(S.enc, pass);
        if (remember) store.set('pass', pass);
        S.pass = pass;
        start(payload);
      } catch (err) {
        renderLock(err && err.message === 'webcrypto'
          ? 'Ce navigateur ne sait pas déchiffrer. Ouvre la page dans Safari ou Chrome, en https.'
          : 'Phrase incorrecte. Vérifie les majuscules, les accents et les espaces.');
      }
    }
  });

  // Bloque le bouton d'envoi d'un formulaire le temps de l'envoi (false si un envoi est déjà en route).
  function lockSubmit(f) {
    const btn = f.querySelector('button[type="submit"]');
    if (!btn) return true;
    if (btn.disabled) return false;
    btn.dataset.label = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Envoi…';
    return true;
  }
  function unlockSubmit(f) {
    const btn = f.isConnected && f.querySelector('button[type="submit"]');
    if (btn) { btn.disabled = false; btn.textContent = btn.dataset.label || 'Envoyer'; }
  }

  async function submitSub(f) {
    const fd = new FormData(f);
    const id = f.dataset.id;
    const num = k => Math.round(parseFloat(String(fd.get(k) || '').replace(',', '.')) * 100) / 100;
    const v = {
      name: String(fd.get('name') || '').trim(),
      amount: num('amount'),
      day: parseInt(fd.get('day'), 10),
      frequency: fd.get('frequency') === 'yearly' ? 'yearly' : 'monthly',
      account: String(fd.get('account') || ''),
      category: String(fd.get('category') || ''),
      approx: fd.get('approx') === 'on',
    };
    const adjustBudget = fd.get('adjustBudget') === 'on';
    if (!v.name || v.name.length > 60) { toast('Donne un nom (60 caractères au plus).', 'warn'); return; }
    if (!Number.isFinite(v.amount) || v.amount <= 0 || v.amount > 2000) { toast('Montant entre 0,01 et 2 000 €.', 'warn'); unlockSubmit(f); return; }
    if (!Number.isInteger(v.day) || v.day < 1 || v.day > 31) { toast('Jour du mois entre 1 et 31.', 'warn'); return; }
    let op;
    if (id) {
      const s = ((S.snap && S.snap.subscriptions) || []).find(x => x.id === id);
      if (!s) { toast('Abonnement introuvable, actualise.', 'warn'); return; }
      op = { op: 'update-sub', id, adjustBudget };
      if (v.name !== s.name) op.name = v.name;
      if (Math.round(v.amount * 100) !== Math.abs(s.amount)) op.amount = v.amount;
      const oldDay = s.day === -1 ? 31 : s.day;
      if (v.day !== oldDay) op.day = v.day;
      if (v.frequency !== (s.frequency === 'yearly' ? 'yearly' : 'monthly')) op.frequency = v.frequency;
      if (v.frequency === 'yearly' && (op.frequency || op.day)) op.month = parseInt(fd.get('month'), 10);
      if (v.account !== s.account) op.account = v.account;
      if (v.category !== s.category) op.category = v.category;
      if (v.approx !== Boolean(s.approx)) op.approx = v.approx;
      if (Object.keys(op).length === 3) { toast('Rien à modifier.', 'warn'); return; }
    } else {
      op = Object.assign({ op: 'add-sub' }, v, { adjustBudget });
      if (v.frequency === 'yearly') op.month = parseInt(fd.get('month'), 10);
      const payee = String(fd.get('payee') || '').trim();
      if (payee) op.payee = payee.slice(0, 60);
    }
    const ok = await sendOps([op], `Abonnement « ${v.name} » ${id ? 'modifié' : 'ajouté'}`);
    if (ok) { S.form = null; render(); }
  }

  function exportBackup() {
    const data = {};
    store.keys().filter(k => k !== 'pass').forEach(k => { data[k] = store.get(k, null); });
    const text = JSON.stringify({ app: 'cap90', at: new Date().toISOString(), data });
    const ta = document.getElementById('backup-text');
    const msg = document.getElementById('backup-msg');
    ta.value = text;
    const fallback = () => { ta.focus(); ta.select(); msg.textContent = 'Texte sélectionné : copie-le avec le menu du téléphone.'; };
    try {
      navigator.clipboard.writeText(text).then(() => { msg.textContent = 'Sauvegarde copiée. Colle-la dans tes notes.'; }, fallback);
    } catch (err) { fallback(); }
  }

  function importBackup() {
    const ta = document.getElementById('backup-text');
    const msg = document.getElementById('backup-msg');
    try {
      const obj = JSON.parse(ta.value);
      if (!obj || obj.app !== 'cap90' || typeof obj.data !== 'object') throw new Error('format');
      Object.entries(obj.data).forEach(([k, v]) => { if (k !== 'pass') store.set(k, v); });
      render();
      const m2 = document.getElementById('backup-msg');
      if (m2) m2.textContent = 'Sauvegarde restaurée.';
    } catch (err) {
      msg.textContent = "Ce texte n'est pas une sauvegarde Cap 90 valide.";
    }
  }

  window.addEventListener('hashchange', () => { S.view = viewFromHash(); S.sportDay = null; render(); window.scrollTo(0, 0); });
  document.addEventListener('visibilitychange', () => {
    if (document.hidden || !S.plan) return;
    if (Date.now() - (S.loadedAt || 0) > 180000) refreshData(true);
    else if (todayISO() !== S.today) render();
  });

  // ---------- démarrage ----------
  async function boot() {
    renderShell();
    S.view = viewFromHash();
    markTabs();
    let src;
    try { src = await loadSource(); } catch (e) { renderEmpty(); return; }
    if (src.payload) { start(src.payload); return; }
    S.enc = src.enc;
    const saved = store.get('pass', null);
    if (saved) {
      try { start(await decrypt(src.enc, saved)); return; } catch (e) { store.del('pass'); }
    }
    renderLock();
  }

  if ('serviceWorker' in navigator && !window.__CAP90__ && location.protocol === 'https:') {
    navigator.serviceWorker.register('sw.js').catch(() => { /* hors ligne indisponible */ });
  }
  boot();
})();
