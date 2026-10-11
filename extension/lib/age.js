export const BANDS = Object.freeze({
  under13: { label: 'Under 13', minimum: 0 },
  '13to15': { label: '13–15', minimum: 13 },
  '16to17': { label: '16–17', minimum: 16 },
  '18plus': { label: '18+', minimum: 18 }
});

export function ageFromDob(dob, now = new Date()) {
  if (typeof dob !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(dob)) return null;
  const birth = new Date(dob + 'T00:00:00.000Z');
  if (!Number.isFinite(birth.getTime()) || birth.toISOString().slice(0, 10) !== dob) return null;
  let age = now.getUTCFullYear() - birth.getUTCFullYear();
  if (now.getUTCMonth() < birth.getUTCMonth() ||
      (now.getUTCMonth() === birth.getUTCMonth() && now.getUTCDate() < birth.getUTCDate())) age--;
  return age >= 0 && age <= 120 ? age : null;
}

export function bandFromDob(dob, now = new Date()) {
  const age = ageFromDob(dob, now);
  if (age === null) return null;
  return age < 13 ? 'under13' : age < 16 ? '13to15' : age < 18 ? '16to17' : '18plus';
}

export function bandAllows(band, minimumAge) {
  return Object.hasOwn(BANDS, band) && Number.isInteger(minimumAge) &&
    minimumAge >= 0 && BANDS[band].minimum >= minimumAge;
}
