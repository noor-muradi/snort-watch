import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { parseRetentionDays, pruneAlertFile } from "../server/alert-retention.mjs";

test("validates retention day settings", () => {
  assert.equal(parseRetentionDays(undefined, "ALERT_RETENTION_DAYS", 30), 30);
  assert.equal(parseRetentionDays("14", "ALERT_RETENTION_DAYS", 30), 14);
  for (const value of ["0", "-1", "1.5", "3651", "abc"]) {
    assert.throws(
      () => parseRetentionDays(value, "ALERT_RETENTION_DAYS", 30),
      /ALERT_RETENTION_DAYS must be a whole number/,
    );
  }
});

test("prunes expired alerts while preserving recent and undated records", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "snort-watch-alert-retention-"));
  const filePath = path.join(directory, "alerts.jsonl");
  const now = new Date("2026-11-13T12:00:00.000Z");
  const records = [
    { received_at: "2026-11-01T12:00:00.000Z", message: "expired" },
    { received_at: "2026-11-12T12:00:00.000Z", message: "recent" },
    { timestamp: "11/12-14:12:34.123456", message: "legacy" },
    { message: "undated" },
  ];

  try {
    await writeFile(filePath, `${records.map((record) => JSON.stringify(record)).join("\n")}\n`);
    const result = await pruneAlertFile(filePath, 7, now);
    const remaining = (await readFile(filePath, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));

    assert.deepEqual(result, { kept: 3, removed: 1 });
    assert.deepEqual(remaining.map((record) => record.message), [
      "recent",
      "legacy",
      "undated",
    ]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
