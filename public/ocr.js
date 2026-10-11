const DOB_LABEL = /\b(?:D[O0Q][B8]|DATE\s*OF\s*B[I1]RTH|B[I1]RTH\s*DATE|B[I1]RTHDATE|B[I1]RTH)\b/i;
const OTHER_DATE_LABEL = /\b(?:EXP(?:IR(?:Y|ATION)?|IRES?)?|EXPIRES|ISS(?:UE|UED)?|VALID\s+FROM|RENEW(?:AL)?)\b/i;
const MONTHS = 'JAN(?:UARY)?|FEB(?:RUARY)?|MAR(?:CH)?|APR(?:IL)?|MAY|JUN(?:E)?|JUL(?:Y)?|AUG(?:UST)?|SEP(?:TEMBER)?|OCT(?:OBER)?|NOV(?:EMBER)?|DEC(?:EMBER)?';
const MONTH_NUMBERS = { JAN: 1, FEB: 2, MAR: 3, APR: 4, MAY: 5, JUN: 6, JUL: 7, AUG: 8, SEP: 9, OCT: 10, NOV: 11, DEC: 12 };

function normalizeDate(year, month, day, today) {
  let fullYear = Number(year);
  if (String(year).length === 2) {
    const currentYear = today.getUTCFullYear();
    fullYear = Math.floor(currentYear / 100) * 100 + fullYear;
    if (fullYear > currentYear) fullYear -= 100;
  }
  const value = [fullYear, String(month).padStart(2, '0'), String(day).padStart(2, '0')].join('-');
  const date = new Date(value + 'T00:00:00Z');
  if (!Number.isFinite(date.getTime()) || date.toISOString().slice(0, 10) !== value || date > today) return '';
  let age = today.getUTCFullYear() - fullYear;
  if (today.getUTCMonth() < date.getUTCMonth() ||
      (today.getUTCMonth() === date.getUTCMonth() && today.getUTCDate() < date.getUTCDate())) age--;
  return age >= 0 && age <= 120 ? value : '';
}

function addCandidate(candidates, start, end, isoDate, text) {
  if (!isoDate) return;
  const lineStart = text.lastIndexOf('\n', start - 1) + 1;
  const lineEnd = text.indexOf('\n', end);
  const line = text.slice(lineStart, lineEnd < 0 ? text.length : lineEnd);
  candidates.push({ start, isoDate, line, labelDistance: Infinity });
}

export function dateFromOcr(text, today = new Date()) {
  if (typeof text !== 'string' || !text.trim()) return '';
  const candidates = [];
  const isoPattern = /\b(19\d{2}|20\d{2})[./-](\d{1,2})[./-](\d{1,2})\b/g;
  for (const match of text.matchAll(isoPattern)) {
    addCandidate(candidates, match.index, match.index + match[0].length,
      normalizeDate(match[1], match[2], match[3], today), text);
  }
  const numericPattern = /\b(\d{1,2})[./\-\s](\d{1,2})[./\-\s](\d{2,4})\b/g;
  for (const match of text.matchAll(numericPattern)) {
    if (match.index > 0 && /\d/.test(text[match.index - 1])) continue;
    const [, firstText, secondText, year] = match;
    const first = Number(firstText), second = Number(secondText);
    const separator = match[0].match(/[./\-\s]/)?.[0] || '/';
    const dayFirst = first > 12 || (second <= 12 && separator === '.');
    const month = dayFirst ? second : first;
    const day = dayFirst ? first : second;
    addCandidate(candidates, match.index, match.index + match[0].length,
      normalizeDate(year, month, day, today), text);
  }
  const monthFirstPattern = new RegExp(`\\b(${MONTHS})[,.\\s-]+(\\d{1,2})(?:st|nd|rd|th)?[,.\\s-]+(19\\d{2}|20\\d{2})\\b`, 'gi');
  for (const match of text.matchAll(monthFirstPattern)) {
    addCandidate(candidates, match.index, match.index + match[0].length,
      normalizeDate(match[3], MONTH_NUMBERS[match[1].slice(0, 3).toUpperCase()], match[2], today), text);
  }
  const dayFirstPattern = new RegExp(`\\b(\\d{1,2})[,.\\s-]+(${MONTHS})[,.\\s-]+(19\\d{2}|20\\d{2})\\b`, 'gi');
  for (const match of text.matchAll(dayFirstPattern)) {
    addCandidate(candidates, match.index, match.index + match[0].length,
      normalizeDate(match[3], MONTH_NUMBERS[match[2].slice(0, 3).toUpperCase()], match[1], today), text);
  }
  if (!candidates.length) return '';

  const labels = [...text.matchAll(new RegExp(DOB_LABEL.source, 'gi'))].map(match => match.index);
  for (const candidate of candidates) {
    if (OTHER_DATE_LABEL.test(candidate.line) && !DOB_LABEL.test(candidate.line)) continue;
    if (labels.length) candidate.labelDistance = Math.min(...labels.map(index => Math.abs(index - candidate.start)));
  }
  const labeled = candidates.filter(candidate => candidate.labelDistance <= 120)
    .sort((left, right) => left.labelDistance - right.labelDistance);
  if (labeled.length) return labeled[0].isoDate;

  const unlabeled = candidates.filter(candidate => !OTHER_DATE_LABEL.test(candidate.line));
  if (!unlabeled.length) return '';
  return unlabeled.sort((left, right) => left.isoDate.localeCompare(right.isoDate))[0].isoDate;
}

export function ageFromDob(dob, today = new Date()) {
  if (typeof dob !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(dob)) return null;
  const birth = new Date(dob + 'T00:00:00Z');
  if (!Number.isFinite(birth.getTime()) || birth.toISOString().slice(0, 10) !== dob || birth > today) return null;
  let age = today.getUTCFullYear() - birth.getUTCFullYear();
  if (today.getUTCMonth() < birth.getUTCMonth() ||
      (today.getUTCMonth() === birth.getUTCMonth() && today.getUTCDate() < birth.getUTCDate())) age--;
  return age >= 0 && age <= 120 ? age : null;
}

export function ageLabelFromDob(dob, today = new Date()) {
  const age = ageFromDob(dob, today);
  if (age === null) return '';
  return age < 13 ? 'Under 13' : age < 16 ? '13–15' : age < 18 ? '16–17' : 'Adult (18+)';
}