chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== "VEILPASTE_OPEN_OPTIONS") {
    return false;
  }

  chrome.runtime.openOptionsPage(() => {
    if (chrome.runtime.lastError) {
      console.error("[VeilPaste] background failed to open options", chrome.runtime.lastError.message);
      sendResponse({ ok: false, error: chrome.runtime.lastError.message });
      return;
    }
    sendResponse({ ok: true });
  });
  return true;
});
