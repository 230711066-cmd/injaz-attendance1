// Baghdad uses UTC+03:00 throughout the year. Server time is authoritative.
export function attendanceException(kind, date = new Date()) {
  const local = new Date(date.getTime() + 3 * 3600000);
  const seconds = local.getUTCHours() * 3600 + local.getUTCMinutes() * 60 + local.getUTCSeconds();
  return kind === 'in' && seconds > 9 * 3600 ? 'late'
    : kind === 'out' && seconds < 17 * 3600 ? 'early' : '';
}
