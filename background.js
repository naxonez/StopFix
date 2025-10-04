// background.js - service worker
const LOG_KEY = 'clip_detector_logs';

// store a log entry
async function pushLog(entry) {
    try {
        const { [LOG_KEY]: existing } = await chrome.storage.local.get(LOG_KEY) || {};
        const arr = Array.isArray(existing) ? existing : [];
        arr.unshift(entry);
        // keep only last 200
        await chrome.storage.local.set({ [LOG_KEY]: arr.slice(0, 200) });
    } catch (e) {
        console.error('[CD] pushLog error', e);
    }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!msg || msg.type !== 'clip_detected') return;
    const payload = msg.payload || {};
    const entry = {
        ts: payload.ts || Date.now(),
        reason: payload.reason || payload.error || 'unknown',
        text: payload.text,
        url: (sender.tab && sender.tab.url) || location?.href || 'unknown',
        tabId: sender.tab && sender.tab.id
    };
    console.warn('[CD BG] Detected clipboard attempt:', entry);
    pushLog(entry);
    sendResponse({ ok: true });
    return true;
});
