import { open } from "node:fs/promises";
import { createInterface } from "node:readline";

export async function readAlertRecords(filePath) {
  const handle = await open(filePath, "r");
  try {
    const fileStat = await handle.stat();
    if (!fileStat.isFile()) {
      throw new Error("The configured Snort JSON path is not a file.");
    }

    const alerts = [];
    let malformedLines = 0;
    const lines = createInterface({
      input: handle.createReadStream({ autoClose: false }),
      crlfDelay: Infinity,
    });

    for await (const line of lines) {
      if (!line.trim()) continue;
      try {
        const value = JSON.parse(line);
        if (!value || typeof value !== "object" || Array.isArray(value)) {
          malformedLines += 1;
          continue;
        }
        alerts.push(value);
      } catch {
        malformedLines += 1;
      }
    }

    return { alerts, malformedLines };
  } finally {
    await handle.close();
  }
}
