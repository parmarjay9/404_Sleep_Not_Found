import { BANDS } from './lib/age.js';
const $ = id => document.getElementById(id);
const buttons = ['login', 'enroll', 'logout'];
const message = (text, bad = false) => { $('message').textContent = text; $('message').className = bad ? 'message bad' : 'message'; };
function render(state) {
  $('loginForm').hidden = state.signedIn;
  $('enroll').hidden = !state.signedIn;
  $('enroll').textContent = state.verified ? 'Renew my pass' : 'Activate my pass';
  $('logout').hidden = !state.signedIn && !state.verified;
  $('passLabel').textContent = state.verified ? 'Signed age pass' : 'No active age pass';
  $('band').textContent = state.verified ? BANDS[state.band].label : 'Let’s get connected.';
  $('expiry').textContent = state.verified ? 'Expires ' + new Date(state.exp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ' · checked at each rated visit' : 'Rated sites stay locked until your age is verified.';
}
async function action(type, fields = {}) {
  buttons.forEach(id => $(id).disabled = true);
  message(type === 'status' ? '' : 'Checking…');
  try {
    const result = await chrome.runtime.sendMessage({ type, ...fields });
    if (!result || result.error) throw new Error(result?.error || 'The extension did not respond. Reload it in Chrome.');
    if (result.sites) render(result);
    message(result.note || (type === 'enroll' ? 'Your pass is ready. Open a covered site to try it.' : type === 'login' ? 'Signed in. Activate your pass next.' : ''));
  } catch (error) { message(error.message, true); }
  finally { buttons.forEach(id => $(id).disabled = false); }
}
$('loginForm').onsubmit = async event => {
  event.preventDefault();
  const password = $('password').value;
  $('password').value = '';
  await action('login', { email: $('email').value.trim(), password });
};
$('enroll').onclick = () => action('enroll');
$('logout').onclick = () => action('logout');
action('status');
