import { appendFile, mkdir, open, stat } from "node:fs/promises";
import path from "node:path";
import { StringDecoder } from "node:string_decoder";
import { fileURLToPath } from "node:url";
import { parseRetentionDays, pruneAlertFile } from "./alert-retention.mjs";
import { parseSnortFastAlert } from "./snort-fast.js";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sourcePath = path.resolve(
  process.env.SNORT_FAST_LOG ?? "/var/log/snort/snort.alert.fast",
);
const outputPath = path.resolve(
  process.env.SNORT_JSON_LOG ?? path.join(projectRoot, "data", "alerts.jsonl"),
);
const intervalMs = Number(process.env.SNORT_BRIDGE_INTERVAL_MS ?? 1000);
const replayExisting = process.env.SNORT_BRIDGE_FROM_START === "1";
const alertRetentionDays = parseRetentionDays(
  process.env.ALERT_RETENTION_DAYS,
  "ALERT_RETENTION_DAYS",
  30,
);
const retentionCheckIntervalMs = 60 * 60 * 1000;
if (!Number.isInteger(intervalMs) || intervalMs < 100) {
  throw new Error("SNORT_BRIDGE_INTERVAL_MS must be an integer of at least 100.");
}

let fileIdentity = null;
let offset = 0;
let pending = "";
let decoder = new StringDecoder("utf8");
let pollRunning = false;
let sourceWasMissing = false;
let lastRetentionCheck = 0;

async function writeAlert(line) {
  const alert = parseSnortFastAlert(line);
  if (!alert) {
    if (line.trim()) {
      console.warn("Skipping unrecognized Snort fast alert line.");
    }
    return;
  }

  await appendFile(
    outputPath,
    `${JSON.stringify({ ...alert, received_at: new Date().toISOString() })}\n`,
    { mode: 0o640 },
  );
}

async function poll() {
  if (pollRunning) {
    return;
  }
  pollRunning = true;

  try {
    const sourceStat = await stat(sourcePath);
    const nextIdentity = `${sourceStat.dev}:${sourceStat.ino}`;

    if (fileIdentity !== nextIdentity || sourceStat.size < offset) {
      const firstRead = fileIdentity === null;
      fileIdentity = nextIdentity;
      offset =
        firstRead && !replayExisting && !sourceWasMissing
          ? sourceStat.size
          : 0;
      sourceWasMissing = false;
      pending = "";
      decoder = new StringDecoder("utf8");
      if (firstRead && !replayExisting) {
        console.info(`Following new alerts in ${sourcePath}`);
        return;
      }
    }

    if (sourceStat.size <= offset) {
      return;
    }

    const start = offset;
    offset = sourceStat.size;
    const handle = await open(sourcePath, "r");
    try {
      const stream = handle.createReadStream({ start, end: offset - 1 });
      for await (const chunk of stream) {
        pending += decoder.write(chunk);
        const lines = pending.split(/\r?\n/);
        pending = lines.pop() ?? "";
        for (const line of lines) {
          await writeAlert(line);
        }
      }
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (error.code === "ENOENT") {
      sourceWasMissing = true;
      console.error(`Snort fast log not found: ${sourcePath}`);
    } else {
      console.error("Could not read or convert the Snort fast log:", error);
    }
  } finally {
    if (Date.now() - lastRetentionCheck >= retentionCheckIntervalMs) {
      lastRetentionCheck = Date.now();
      try {
        const result = await pruneAlertFile(outputPath, alertRetentionDays);
        if (result.removed > 0) {
          console.info(
            `Alert retention removed ${result.removed} records older than ${alertRetentionDays} days.`,
          );
        }
      } catch (error) {
        console.error(`Could not apply alert retention to ${outputPath}:`, error);
      }
    }
    pollRunning = false;
  }
}

await mkdir(path.dirname(outputPath), { recursive: true });
const outputFile = await open(outputPath, "a", 0o640);
await outputFile.close();
await poll();
setInterval(poll, intervalMs);
