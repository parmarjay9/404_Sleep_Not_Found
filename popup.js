const out = document.getElementById('out');
const ask = m => chrome.runtime.sendMessage(m, r => out.textContent = JSON.stringify(r, null, 1));
document.getElementById('enroll').onclick = () => ask({ type: 'enroll', dob: document.getElementById('dob').value });
document.getElementById('extract').onclick = () => ask({ type: 'extract' });
