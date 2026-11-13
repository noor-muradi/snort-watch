import { createReadStream } from "node:fs";
import { open, rename, unlink } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { createInterface } from "node:readline";
import path from "node:path";

const LEGACY_TIMESTAMP =
  /^(\d{2})\/(\d{2})-(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$/;

export function parseRetentionDays(value, name, defaultDays) {
  const raw = value ?? String(defaultDays);
  if (!/^\d+$/.test(raw)) {
    throw new Error(`${name} must be a whole number between 1 and 3650.`);
  }
  const days = Number(raw);
  if (!Number.isSafeInteger(days) || days < 1 || days > 3650) {
    throw new Error(`${name} must be a whole number between 1 and 3650.`);
  }
  return days;
}

function alertTimestamp(alert, now) {
  if (typeof alert.received_at === "string") {
    const receivedAt = Date.parse(alert.received_at);
    if (Number.isFinite(receivedAt)) return receivedAt;
  }

  if (typeof alert.timestamp !== "string") return null;
  const match = LEGACY_TIMESTAMP.exec(alert.timestamp);
  if (!match) return null;

  const [, monthText, dayText, hourText, minuteText, secondText, fraction = ""] = match;
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const milliseconds = Number(`0.${fraction}`) * 1000;
  const year = now.getFullYear();
  const timestamp = new Date(
    year,
    month - 1,
    day,
    hour,
    minute,
    second,
    milliseconds,
  );
  if (
    timestamp.getMonth() !== month - 1 ||
    timestamp.getDate() !== day ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    return null;
  }
  if (timestamp.getTime() > now.getTime() + 24 * 60 * 60 * 1000) {
    timestamp.setFullYear(year - 1);
  }
  return timestamp.getTime();
}

export async function pruneAlertFile(filePath, retentionDays, now = new Date()) {
  const cutoff = now.getTime() - retentionDays * 24 * 60 * 60 * 1000;
  const temporaryPath = path.join(
    path.dirname(filePath),
    `.${path.basename(filePath)}.${randomUUID()}.tmp`,
  );
  const output = await open(temporaryPath, "wx", 0o640);
  let removed = 0;
  let kept = 0;
  let complete = false;
  let outputClosed = false;

  try {
    const lines = createInterface({
      input: createReadStream(filePath),
      crlfDelay: Infinity,
    });
    for await (const line of lines) {
      if (!line.trim()) continue;

      let expired = false;
      try {
        const alert = JSON.parse(line);
        const timestamp = alert && typeof alert === "object" && !Array.isArray(alert)
          ? alertTimestamp(alert, now)
          : null;
        expired = timestamp !== null && timestamp < cutoff;
      } catch {
        expired = false;
      }

      if (expired) {
        removed += 1;
      } else {
        await output.writeFile(`${line}\n`);
        kept += 1;
      }
    }

    await output.sync();
    await output.close();
    outputClosed = true;
    await rename(temporaryPath, filePath);
    complete = true;
    return { kept, removed };
  } finally {
    if (!outputClosed) await output.close();
    if (!complete) {
      await unlink(temporaryPath).catch((error) => {
        if (error.code !== "ENOENT") throw error;
      });
    }
  }
}
