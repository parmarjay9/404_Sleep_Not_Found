const out = document.getElementById('out');
const say = (text, color) => { out.textContent = text; out.style.color = color; };

document.getElementById('enroll').onclick = () => {
  const dob = document.getElementById('dob').value;
  chrome.runtime.sendMessage({ type: 'enroll', dob }, r => {
    if (r && r.ok) say('✅ Verified as an adult. Reload the restricted page.', 'green');
    else say('❌ Verification failed: ' + ((r && r.error) || 'no response'), 'crimson');
  });
};

document.getElementById('extract').onclick = () => {
  chrome.runtime.sendMessage({ type: 'extract' }, r => {
    if (r && r.error) say('🔒 Attack blocked: the private key cannot be extracted.', 'green');
    else say('⚠️ Key was extracted (this should never happen).', 'crimson');
  });
};