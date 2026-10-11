chrome.runtime.sendMessage({ type: 'content' }, result => {
  const slot = document.getElementById('slot');
  if (!slot) return;
  if (chrome.runtime.lastError) { slot.textContent = 'Enable the WebCompass extension, then reload this page.'; return; }
  if (result?.meme) {
    const image = document.createElement('img');
    image.src = result.meme; image.alt = 'Your signed 18+ age pass and device signature are valid.';
    slot.replaceChildren(image);
  } else slot.textContent = result?.error || 'Activate your age pass in WebCompass, then reload this page.';
});
