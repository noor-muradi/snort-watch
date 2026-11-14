function parseDateValue(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function alertDate(alert, now = new Date()) {
  const receivedAt = typeof alert.received_at === "string"
    ? parseDateValue(alert.received_at)
    : null;
  if (receivedAt) return receivedAt;

  const value = alert.timestamp ?? alert.ts;
  if (typeof value !== "string") return null;

  const snortTime = value.match(
    /^(\d{2})\/(\d{2})-(\d{2}:\d{2}:\d{2}(?:\.\d+)?)$/,
  );
  if (!snortTime) return parseDateValue(value);

  const month = Number(snortTime[1]);
  const day = Number(snortTime[2]);
  if (month < 1 || month > 12 || day < 1 || day > 31) return null;
  const [hour, minute, seconds] = snortTime[3].split(":");
  const [second, fraction = ""] = seconds.split(".");
  const milliseconds = Number(`0.${fraction}`) * 1000;

  const candidates = [now.getFullYear() - 1, now.getFullYear(), now.getFullYear() + 1]
    .map((year) =>
      new Date(
        year,
        month - 1,
        day,
        Number(hour),
        Number(minute),
        Number(second),
        milliseconds,
      )
    )
    .filter((date) =>
      !Number.isNaN(date.getTime()) &&
      date.getMonth() === month - 1 &&
      date.getDate() === day
    );
  if (candidates.length === 0) return null;

  return candidates.reduce((nearest, candidate) =>
    Math.abs(candidate.getTime() - now.getTime()) <
    Math.abs(nearest.getTime() - now.getTime())
      ? candidate
      : nearest
  );
}

export function localDateStart(value) {
  if (!value) return null;
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!match) return null;
  const date = new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
  if (
    date.getFullYear() !== Number(match[1]) ||
    date.getMonth() !== Number(match[2]) - 1 ||
    date.getDate() !== Number(match[3])
  ) {
    return null;
  }
  return date;
}

export function isWithinAlertDateRange(alert, startDate, endDate, now = new Date()) {
  if (!startDate && !endDate) return true;
  const date = alertDate(alert, now);
  if (!date) return false;
  const endExclusive = endDate
    ? new Date(endDate.getFullYear(), endDate.getMonth(), endDate.getDate() + 1)
    : null;
  return (!startDate || date >= startDate) && (!endExclusive || date < endExclusive);
}
