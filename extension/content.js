chrome.runtime.sendMessage({ type: 'content' }, r => {
  const slot = document.getElementById('slot');
  if (r && r.meme) { const i = document.createElement('img'); i.src = r.meme; slot.replaceChildren(i); }
  else slot.textContent = '🔒 Locked: ' + ((r && r.error) || 'no response');
});
