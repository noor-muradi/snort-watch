import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, utimes, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  parsePositiveMegabytes,
  SnortLogRetention,
} from "../server/snort-log-retention.mjs";

test("validates Snort log rotation size settings", () => {
  assert.equal(parsePositiveMegabytes(undefined, "SNORT_LOG_ROTATE_SIZE_MB", 100), 100);
  assert.equal(parsePositiveMegabytes("25", "SNORT_LOG_ROTATE_SIZE_MB", 100), 25);
  for (const value of ["0", "-1", "1.5", "102401", "abc"]) {
    assert.throws(
      () => parsePositiveMegabytes(value, "SNORT_LOG_ROTATE_SIZE_MB", 100),
      /SNORT_LOG_ROTATE_SIZE_MB must be a whole number/,
    );
  }
});

test("rotates oversized Snort logs and prunes expired archives", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "snort-watch-log-retention-"));
  const logPath = path.join(directory, "snort.alert.fast");
  const now = new Date("2026-11-13T12:00:00.000Z");
  let restarts = 0;
  const supervisor = {
    child: {},
    async restartWith(beforeStart) {
      this.child = null;
      await beforeStart();
      this.child = {};
      restarts += 1;
    },
    async start() {
      this.child = {};
    },
  };
  const retention = new SnortLogRetention({
    directory,
    supervisor,
    retentionDays: 7,
    rotateSizeBytes: 4,
  });

  try {
    await writeFile(logPath, "oversized log");
    await utimes(logPath, now, now);
    const expiredArchive = path.join(
      directory,
      "snort.alert.fast.rotated-2026-11-01T00-00-00-000Z",
    );
    await writeFile(expiredArchive, "expired");
    await utimes(
      expiredArchive,
      new Date("2026-11-01T00:00:00.000Z"),
      new Date("2026-11-01T00:00:00.000Z"),
    );

    const result = await retention.run(now);
    const names = await readdir(directory);
    const archiveName = names.find((name) => name.includes(".rotated-"));

    assert.deepEqual(result, { rotated: true, removed: 1 });
    assert.equal(restarts, 1);
    assert.ok(archiveName);
    assert.equal(
      await readFile(path.join(directory, archiveName), "utf8"),
      "oversized log",
    );
    assert.equal(names.includes(path.basename(expiredArchive)), false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("restores active log names if a Snort restart fails during rotation", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "snort-watch-log-rollback-"));
  const logPath = path.join(directory, "snort.alert.fast");
  const now = new Date("2026-11-13T12:00:00.000Z");
  let starts = 0;
  const supervisor = {
    child: {},
    async restartWith(beforeStart) {
      this.child = null;
      await beforeStart();
      throw new Error("Snort failed to start.");
    },
    async start() {
      this.child = {};
      starts += 1;
    },
  };
  const retention = new SnortLogRetention({
    directory,
    supervisor,
    retentionDays: 7,
    rotateSizeBytes: 4,
  });

  try {
    await writeFile(logPath, "oversized log");
    await utimes(logPath, now, now);
    await assert.rejects(retention.run(now), /Snort failed to start/);
    assert.equal(await readFile(logPath, "utf8"), "oversized log");
    assert.equal(starts, 1);
    assert.deepEqual(await readdir(directory), ["snort.alert.fast"]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("rotates active Snort logs after the UTC day changes", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "snort-watch-daily-rotation-"));
  const logPath = path.join(directory, "snort.alert.fast");
  const now = new Date("2026-11-13T00:01:00.000Z");
  let restarts = 0;
  const supervisor = {
    child: {},
    async restartWith(beforeStart) {
      this.child = null;
      await beforeStart();
      this.child = {};
      restarts += 1;
    },
    async start() {
      this.child = {};
    },
  };
  const retention = new SnortLogRetention({
    directory,
    supervisor,
    retentionDays: 7,
    rotateSizeBytes: 1024,
  });

  try {
    await writeFile(logPath, "previous day");
    const previousDay = new Date("2026-11-12T23:59:00.000Z");
    await utimes(logPath, previousDay, previousDay);

    const result = await retention.run(now);

    assert.deepEqual(result, { rotated: true, removed: 0 });
    assert.equal(restarts, 1);
    assert.equal((await readdir(directory)).length, 1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("waits for an active rotation before stopping retention checks", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "snort-watch-retention-stop-"));
  const logPath = path.join(directory, "snort.alert.fast");
  const now = new Date("2026-11-13T12:00:00.000Z");
  let releaseRestart;
  let notifyRotationStarted;
  const restartGate = new Promise((resolve) => {
    releaseRestart = resolve;
  });
  const rotationStarted = new Promise((resolve) => {
    notifyRotationStarted = resolve;
  });
  const supervisor = {
    child: {},
    async restartWith(beforeStart) {
      this.child = null;
      await beforeStart();
      notifyRotationStarted();
      await restartGate;
      this.child = {};
    },
  };
  const retention = new SnortLogRetention({
    directory,
    supervisor,
    retentionDays: 7,
    rotateSizeBytes: 4,
  });

  try {
    await writeFile(logPath, "oversized log");
    await utimes(logPath, now, now);
    const activeRun = retention.run(now);
    await rotationStarted;

    let stopped = false;
    const stop = retention.stop().then(() => {
      stopped = true;
    });
    await Promise.resolve();
    assert.equal(stopped, false);

    releaseRestart();
    await Promise.all([activeRun, stop]);
    assert.equal(stopped, true);
  } finally {
    releaseRestart();
    await rm(directory, { recursive: true, force: true });
  }
});
