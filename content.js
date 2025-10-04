// content.js - run_at document_start, all_frames: true
(function () {
  // Inyecta page_inject.js en el contexto de la página/frame (archivo externo para evitar CSP inline)
  try {
    const s = document.createElement('script');
    s.src = chrome.runtime.getURL('page_inject.js');
    s.type = 'text/javascript';
    (document.documentElement || document.head || document.body || document).appendChild(s);
    s.onload = () => { try { s.remove(); } catch (e) {} };
  } catch (e) {
    console.error('[CD] injection error', e);
  }

  // =========================
  // Modal/UI (isolation using Shadow DOM)
  // =========================
  function createIsolatedModal({ text = '', reason = '' } = {}) {
    // evitar duplicados
    if (document.getElementById('clip-detector-overlay-host')) return;

    // host appended to documentElement (outside body when possible)
    const host = document.createElement('div');
    host.id = 'clip-detector-overlay-host';
    host.style.position = 'fixed';
    host.style.inset = '0';
    host.style.zIndex = '2147483647';
    host.style.pointerEvents = 'none';

    // attach shadow root (open so we can manipulate)
    const shadow = host.attachShadow({ mode: 'open' });

    const modalHtml = `
      <style>
        :host { all: initial; }
        .backdrop {
          position: fixed;
          inset: 0;
          display: flex;
          align-items: center;
          justify-content: center;
          background: rgba(0,0,0,0.45);
          pointer-events: auto;
          z-index: 2147483647;
        }
        .modal {
          width: 520px;
          max-width: calc(100% - 40px);
          background: #fff;
          color: #111;
          border-radius: 10px;
          padding: 18px;
          box-shadow: 0 10px 30px rgba(0,0,0,0.4);
          font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
          line-height: 1.2;
        }
        .title { font-weight: 700; margin-bottom: 8px; font-size: 16px; color: #b30000; }
        .desc { margin-bottom: 12px; font-size: 13px; color: #222; }
        pre { background: #f7f7f7; padding: 10px; border-radius: 6px; max-height: 240px; overflow: auto; white-space: pre-wrap; word-break: break-all; margin: 0 0 12px 0; font-size:12px; }
        .actions { text-align: right; }
        button { margin-left:8px; padding:8px 12px; border-radius:6px; border: none; cursor: pointer; font-weight:600; }
        button#ignore { background: #e0e0e0; color: #111; }
        button#clean { background: #b30000; color: #fff; }
      </style>

      <div class="backdrop" id="cd-backdrop" role="dialog" aria-modal="true">
        <div class="modal" role="document">
          <div class="title">⚠️ Posible ataque detectado</div>
          <div class="desc">Se ha detectado contenido sospechoso que intentó copiarse al portapapeles. Revisa el contenido y elige una acción.</div>
          <pre id="cd-text"></pre>
          <div class="actions">
            <button id="ignore">Ignorar</button>
            <button id="clean">Limpiar clipboard</button>
          </div>
        </div>
      </div>
    `;

    shadow.innerHTML = modalHtml;
    (document.documentElement || document.body || document).appendChild(host);

    const pre = shadow.getElementById ? shadow.getElementById('cd-text') : shadow.querySelector('#cd-text');
    if (pre) pre.textContent = text || '';

    const ignoreBtn = shadow.querySelector('#ignore');
    const cleanBtn = shadow.querySelector('#clean');
    const backdrop = shadow.querySelector('.backdrop');

    function removeModal() { try { host.remove(); } catch (e) {} }

    // IGNORAR: NO tocar el clipboard — solo cerrar y registrar
    if (ignoreBtn) ignoreBtn.addEventListener('click', () => {
        try {
            chrome.runtime.sendMessage({ type: 'clip_action', action: 'ignore', text, reason });
        } catch (e) {}
        // No clipboard operations here — se mantiene lo que haya en el portapapeles
        removeModal();
    });

    // LIMPIAR: eliminar el contenido del clipboard (solo aquí)
    if (cleanBtn) cleanBtn.addEventListener('click', async () => {
        try {
            if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
                await navigator.clipboard.writeText('');
            } else {
                // fallback: copiar cadena vacía mediante textarea + execCommand
                const ta = document.createElement('textarea');
                ta.value = '';
                ta.style.position = 'fixed';
                ta.style.left = '-9999px';
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                ta.remove();
            }
            try { chrome.runtime.sendMessage({ type: 'clip_action', action: 'clean', text, reason }); } catch (e) {}
        } catch (err) {
            try { chrome.runtime.sendMessage({ type: 'clip_action', action: 'clean_failed', error: String(err), text, reason }); } catch (e) {}
        }
        removeModal();
    });

    // Click en backdrop solo cierra (NO limpia)
    if (backdrop) backdrop.addEventListener('click', (ev) => {
        if (ev.target === backdrop) removeModal();
    });
  }

  // =========================
  // Message listener: receive detection requests from page_inject.js
  // =========================
window.addEventListener('message', function (event) {
    const msg = event.data;
    if (!msg || typeof msg !== 'object') return;

    // ignorar mensaje de control
    if (msg.text === '__INJECT_OK__') return;
    if (!msg.text || typeof msg.text !== 'string') return;

    // Regexs
    const URL_OR_IP_RE = /\bhttps?:\/\/[^\s"'`<>]{8,}\b|\b(?:\d{1,3}\.){3}\d{1,3}\b/i;
    const FLAGS_OR_INDICATORS_RE = /\b(?:-EncodedCommand\b|-enc\b|-Command\b|\b-?c\b|\b-nop\b|\b-ep\b|\b-NoProfile\b|\b-UseBasicParsing\b|\b-Uri\b|\.ps1\b|\b-join\b|\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|[A-Za-z0-9+\/]{40,}=*)/i;

    // Keywords que queremos condicionar (si aparecen necesitan un indicador)
    const KEYWORDS_RE = /\b(?:powershell|mshta|msiexec|rundll32|regsvr32|certutil|iex\b|iwr\b|Invoke-WebRequest\b|Start-?Bits(?:Transfer)?|bitsadmin\b)\b/i;

    // Decide si es sospechoso: keyword + (url/ip OR flags/indicators)
    const hasKeyword = KEYWORDS_RE.test(msg.text);
    const hasUrlOrIp = URL_OR_IP_RE.test(msg.text);
    const hasIndicator = FLAGS_OR_INDICATORS_RE.test(msg.text);

    const isSuspicious = hasKeyword && (hasUrlOrIp || hasIndicator);

    // Si no es sospechoso, ignorar (reduce FPs como "powershell" suelto)
    if (!isSuspicious) {
        console.debug('[CD] Ignorado (no cumple keyword+indicator):', { text: msg.text, hasKeyword, hasUrlOrIp, hasIndicator });
        return;
    }

    // Si llega aquí, es sospechoso: forward al top para mostrar UI (si estamos en iframe)
    try {
        if (window.top && window.top !== window) {
            window.top.postMessage({ source: 'CLIP_DETECTOR_SHOW_UI', text: msg.text, reason: msg.reason, ts: msg.ts }, '*');
            return;
        }
    } catch (e) { /* ignore cross-origin */ }

    // Si somos top, mostrar modal
    try { createIsolatedModal({ text: msg.text, reason: msg.reason }); } catch (e) { console.error(e); }
}, false);

})();
