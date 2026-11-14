import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { readAlertRecords } from "../server/alerts-file.mjs";

test("reads every valid alert beyond the previous count limit", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "snort-watch-alert-feed-"));
  const filePath = path.join(directory, "alerts.jsonl");
  const count = 2505;

  try {
    const records = Array.from({ length: count }, (_, index) =>
      JSON.stringify({ sequence: index })
    );
    await writeFile(filePath, `${records.join("\n")}\n`);
    const result = await readAlertRecords(filePath);

    assert.equal(result.alerts.length, count);
    assert.equal(result.alerts[0].sequence, 0);
    assert.equal(result.alerts.at(-1).sequence, count - 1);
    assert.equal(result.malformedLines, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("reads records beyond the previous byte scan limit and counts malformed lines", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "snort-watch-large-alert-feed-"));
  const filePath = path.join(directory, "alerts.jsonl");

  try {
    const largeRecord = JSON.stringify({ message: "x".repeat(8 * 1024 * 1024) });
    await writeFile(filePath, `not-json\n${JSON.stringify({ id: 1 })}\n${largeRecord}\n`);
    const result = await readAlertRecords(filePath);

    assert.equal(result.alerts.length, 2);
    assert.equal(result.alerts[0].id, 1);
    assert.equal(result.alerts[1].message.length, 8 * 1024 * 1024);
    assert.equal(result.malformedLines, 1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
