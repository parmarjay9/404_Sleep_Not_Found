export function validateRatings(sites) {
  if (!Array.isArray(sites) || !sites.length || sites.length > 100) throw new Error('Invalid site list.');
  const ids = new Set(), domains = new Set();
  for (const site of sites) {
    if (!site || !/^[a-z0-9-]+$/.test(site.id) || ids.has(site.id) ||
        typeof site.name !== 'string' || typeof site.reason !== 'string' ||
        !Array.isArray(site.domains) || !site.domains.length || ![13, 16, 18].includes(site.minimumAge)) {
      throw new Error('Invalid site rating.');
    }
    ids.add(site.id);
    for (const domain of site.domains) {
      if (typeof domain !== 'string' || !/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(domain) || domains.has(domain)) {
        throw new Error('Invalid or repeated rated domain.');
      }
      domains.add(domain);
    }
  }
  return sites;
}

export function siteForUrl(sites, value) {
  let url;
  try { url = new URL(value); } catch { return null; }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  return sites.find(site => site.domains.some(domain => host === domain || host.endsWith('.' + domain))) || null;
}

// Static redirects work even before the service worker starts, or if the backend is offline.
export function baselineRules(sites) {
  return validateRatings(sites).map((site, index) => ({
    id: index + 1, priority: 1,
    action: { type: 'redirect', redirect: { extensionPath: '/gate.html' } },
    condition: { requestDomains: site.domains, resourceTypes: ['main_frame'] }
  }));
}

export function redirectRules(sites, gateUrl) {
  return validateRatings(sites).map((site, index) => ({
    id: index + 1, priority: 2,
    action: { type: 'redirect', redirect: { regexSubstitution: gateUrl + '?site=' + site.id + '#\\1' } },
    condition: { requestDomains: site.domains, regexFilter: '^(https?://.*)$', resourceTypes: ['main_frame'] }
  }));
}

export function admissionRule(tabId, target) {
  if (!Number.isInteger(tabId) || tabId < 0 || tabId > 2_000_000_000) throw new Error('Invalid browser tab.');
  const escaped = target.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  if (escaped.length > 1000) throw new Error('This link is too long. Open the site homepage instead.');
  return {
    id: 100_000 + tabId, priority: 100,
    action: { type: 'allow' },
    condition: { regexFilter: '^' + escaped + '$', isUrlFilterCaseSensitive: true,
      tabIds: [tabId], resourceTypes: ['main_frame'] }
  };
}
