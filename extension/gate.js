import { BANDS } from './lib/age.js';
const $ = id => document.getElementById(id);
const params = new URLSearchParams(location.search);
const siteId = params.get('site');
// Kept in the extension URL fragment; never sent to the website or the issuer.
const target = location.hash.slice(1);
async function check() {
  $('retry').disabled = true;
  $('message').textContent = 'Checking your pass…';
  try {
    const result = await chrome.runtime.sendMessage({ type: 'gate', siteId, target });
    if (!result || result.error) throw new Error(result?.error || 'The extension is starting. Try checking again.');
    if (result.allowed) { $('message').textContent = 'Your pass checks out. Opening the site…'; return; }
    $('title').textContent = result.state === 'age' ? 'Not for your age just yet.' : result.state === 'check' ? 'We couldn’t finish this check.' : 'One small step before this site.';
    $('description').textContent = result.reason;
    if (result.site) {
      $('explanation').hidden = false;
      $('siteName').textContent = result.site.name;
      $('requirement').textContent = 'This site is rated ' + result.site.minimumAge + '+';
      $('bandLabel').textContent = result.band ? 'Your verified band: ' + BANDS[result.band].label : 'Activate your pass using the WebCompass toolbar button.';
    }
    $('message').textContent = '';
  } catch (error) {
    $('title').textContent = 'Let’s get your browser connected.';
    $('description').textContent = error.message;
    $('message').textContent = '';
  } finally { $('retry').disabled = false; }
}
$('retry').onclick = check;
check();
