const timestamp = /^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):([0-5]\d):([0-5]\d|60)(?:\.(\d+))?(Z|([+-])([01]\d|2[0-3]):([0-5]\d))(?![\s\S])/i;
const monthStarts = [0n, 31n, 59n, 90n, 120n, 151n, 181n, 212n, 243n, 273n, 304n, 334n, 365n];

function isLeapYear(year) {
  return year % 4n === 0n && (year % 100n !== 0n || year % 400n === 0n);
}

function dayNumber(year, month, day) {
  const leapDay = month > 2 && isLeapYear(year) ? 1n : 0n;
  return 365n * year + (year + 3n) / 4n - (year + 99n) / 100n + (year + 399n) / 400n +
    monthStarts[month - 1] + leapDay + day - 1n;
}

const epochDay = dayNumber(1970n, 1, 1n);

// UTC dates with a positive leap second, as announced by the IERS.
const leapSecondDays = new Set([
  "1972-06", "1972-12", "1973-12", "1974-12", "1975-12", "1976-12", "1977-12",
  "1978-12", "1979-12", "1981-06", "1982-06", "1983-06", "1985-06", "1987-12",
  "1989-12", "1990-12", "1992-06", "1993-06", "1994-06", "1995-12", "1997-06",
  "1998-12", "2005-12", "2008-12", "2012-06", "2015-06", "2016-12",
].map((month) => (dayNumber(BigInt(month.slice(0, 4)), Number(month.slice(5)), month.endsWith("06") ? 30n : 31n) -
  epochDay) * 86400n + 86399n));

/** Return the normalized UTC second and fractional digits of an RFC 3339 instant, or null. */
export function parseFixtureInstant(value) {
  const match = typeof value === "string" ? timestamp.exec(value) : null;
  if (!match) return null;
  const [, y, m, d, h, min, sec, fraction = "", , sign, offsetHour, offsetMinute] = match;
  const year = BigInt(y);
  const month = Number(m);
  const day = BigInt(d);
  const lastDay = month === 2 && isLeapYear(year) ? 29n : monthStarts[month] - monthStarts[month - 1];
  if (day > lastDay) return null;

  const offset = sign ? BigInt(offsetHour) * 60n + BigInt(offsetMinute) : 0n;
  const utcMinute = BigInt(h) * 60n + BigInt(min) + (sign === "-" ? offset : -offset);
  const leapSecond = sec === "60";
  const seconds = (dayNumber(year, month, day) - epochDay) * 86400n + utcMinute * 60n +
    (leapSecond ? 59n : BigInt(sec));
  if (leapSecond && !leapSecondDays.has(seconds)) return null;
  let end = fraction.length;
  while (fraction[end - 1] === "0") end--;
  return { seconds, fraction: fraction.slice(0, end), leapSecond };
}
