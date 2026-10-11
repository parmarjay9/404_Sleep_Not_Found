import fs from 'node:fs';
import { baselineRules } from '../extension/lib/policy.js';
const sites = JSON.parse(fs.readFileSync(new URL('../extension/site-ratings.json', import.meta.url)));
const rules = baselineRules(sites);
const manifestFile = new URL('../extension/manifest.json', import.meta.url);
const manifest = JSON.parse(fs.readFileSync(manifestFile));
manifest.host_permissions = ['http://localhost:3000/*', 'https://*.supabase.co/*',
  ...sites.flatMap(site => site.domains.map(domain => '*://*.' + domain + '/*'))];
fs.writeFileSync(new URL('../extension/rules.json', import.meta.url), JSON.stringify(rules, null, 2) + '\n');
fs.writeFileSync(manifestFile, JSON.stringify(manifest, null, 2) + '\n');
console.log('Built redirects and Chrome domain permissions for ' + sites.length + ' site ratings. Reload the extension in Chrome.');
