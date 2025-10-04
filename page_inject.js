// page_inject.js - ejecutado en contexto de la página/frame
(function () {
    try {
        // Regex más completa para detectar payloads tipo ClickFix/FileFix (centrada en PowerShell + iwr/iex + IPs)
        const SUSPICIOUS_RE = /\b(?:powershell(?:\.exe)?|\b-?c\b|\b-EncodedCommand\b|\b-enc\b|\b-?Command\b|\biex\b|\biwr\b|\bInvoke-WebRequest\b|\b-Uri\b|\b-UseBasicParsing\b|\|\s*iex\b|\b-join\b|Start-?Bits(?:Transfer)?|bitsadmin\b|mshta\b|msiexec\b|rundll32\b|regsvr32\b|certutil\b|curl)\b|(?:\b(?:\d{1,3}\.){3}\d{1,3}\b)/i;

        function postDetection(text, reason) {
            try {
                window.postMessage({ source: 'CLIP_DETECTOR_INJECT', text: text, reason: reason, ts: Date.now() }, '*');
                window.postMessage({ source: 'CLIP_DETECTOR_SHOW_UI', text: text, reason: reason, ts: Date.now() }, '*');
            } catch (e) {}
        }

        window.postMessage({ source: 'CLIP_DETECTOR_INJECT', text: '__INJECT_OK__', reason: 'injected' }, '*');

        // 1) Intercept navigator.clipboard.writeText
        try {
            if (navigator && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
                const origWrite = navigator.clipboard.writeText.bind(navigator.clipboard);
                navigator.clipboard.writeText = function (text) {
                    try {
                        if (typeof text === 'string' &&     SUSPICIOUS_RE.test(text)) {
                            postDetection(text, 'navigator.clipboard.writeText');
                        }
                    } catch (e) {}
                    return origWrite(text);
                };
            }
        } catch (e) {}

        // 2) Intercept document.execCommand('copy')
        try {
            const origExec = Document.prototype.execCommand;
            Document.prototype.execCommand = function (cmd) {
                try {
                    if (String(cmd).toLowerCase() === 'copy') {
                        const sel = (window.getSelection && window.getSelection().toString()) || '';
                        if (sel && SUSPICIOUS_RE.test(sel)) {
                            postDetection(sel, 'document.execCommand(copy)');
                            return false;
                        }
                    }
                } catch (e) {}
                return origExec.apply(this, arguments);
            };
        } catch (e) {}

        // 3) Listen 'copy' events to inspect clipboardData / selection
        try {
            window.addEventListener('copy', function (evt) {
                try {
                    const cb = evt.clipboardData || window.clipboardData;
                    const attempted = (cb && cb.getData && cb.getData('text/plain')) || (window.getSelection && window.getSelection().toString()) || '';
                    if (attempted && SUSPICIOUS_RE.test(attempted)) {
                        postDetection(attempted, 'copy-event');
                        // do not overwrite clipboard here — let user decide via UI
                        evt.preventDefault();
                        try { cb && cb.setData && cb.setData('text/plain', attempted); } catch (e) {}
                    }
                } catch (e) {}
            }, true);
        } catch (e) {}

        // 4) MutationObserver: detect textarea/input added with values
        try {
            const mo = new MutationObserver(records => {
                try {
                    records.forEach(r => {
                        (r.addedNodes || []).forEach(node => {
                            if (!node || node.nodeType !== 1) return;
                            const tag = node.tagName && node.tagName.toLowerCase();
                            if (tag === 'textarea' || (tag === 'input' && (node.type === 'text' || node.type === 'hidden'))) {
                                const v = node.value || node.getAttribute && node.getAttribute('value') || '';
                                if (v && SUSPICIOUS_RE.test(v)) {
                                    postDetection(v, 'hidden-textarea-created');
                                }
                            }
                        });
                    });
                } catch (e) {}
            });
            mo.observe(document, { childList: true, subtree: true });
        } catch (e) {}

        // 5) Intercept createElement('textarea') to detect value writes
        try {
            const origCreate = Document.prototype.createElement;
            Document.prototype.createElement = function (name) {
                const el = origCreate.apply(this, arguments);
                try {
                    if (String(name).toLowerCase() === 'textarea') {
                        const desc = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value');
                        if (desc && desc.set) {
                            Object.defineProperty(el, 'value', {
                                set: function (v) {
                                    try {
                                        if (typeof v === 'string' && SUSPICIOUS_RE.test(v)) {
                                            postDetection(v, 'textarea.value-set');
                                        }
                                    } catch (e) {}
                                    return desc.set.call(this, v);
                                },
                                get: desc.get,
                                configurable: true,
                                enumerable: true
                            });
                        }
                    }
                } catch (e) {}
                return el;
            };
        } catch (e) {}

    } catch (err) {
        try { window.postMessage({ source: 'CLIP_DETECTOR_INJECT', error: '' + err }, '*'); } catch (e) {}
    }
})();
