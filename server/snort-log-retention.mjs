import { readdir, rename, stat, unlink, utimes } from "node:fs/promises";
import path from "node:path";

const ARCHIVE_SUFFIX = /\.rotated-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z$/;

export function parsePositiveMegabytes(value, name, defaultMegabytes) {
  const raw = value ?? String(defaultMegabytes);
  if (!/^\d+$/.test(raw)) {
    throw new Error(`${name} must be a whole number between 1 and 102400.`);
  }
  const megabytes = Number(raw);
  if (!Number.isSafeInteger(megabytes) || megabytes < 1 || megabytes > 102400) {
    throw new Error(`${name} must be a whole number between 1 and 102400.`);
  }
  return megabytes;
}

function rotationTimestamp(date) {
  return date.toISOString().replaceAll(":", "-").replace(".", "-");
}

async function regularLogFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (!entry.isFile() || ARCHIVE_SUFFIX.test(entry.name)) continue;
    const filePath = path.join(directory, entry.name);
    files.push({ name: entry.name, path: filePath, stats: await stat(filePath) });
  }
  return files;
}

export class SnortLogRetention {
  constructor({ directory, supervisor, retentionDays, rotateSizeBytes }) {
    this.directory = directory;
    this.supervisor = supervisor;
    this.retentionDays = retentionDays;
    this.rotateSizeBytes = rotateSizeBytes;
    this.currentRun = null;
    this.stopping = false;
  }

  async pruneArchives(now) {
    const cutoff = now.getTime() - this.retentionDays * 24 * 60 * 60 * 1000;
    const entries = await readdir(this.directory, { withFileTypes: true });
    let removed = 0;
    for (const entry of entries) {
      if (!entry.isFile() || !ARCHIVE_SUFFIX.test(entry.name)) continue;
      const filePath = path.join(this.directory, entry.name);
      const fileStats = await stat(filePath);
      if (fileStats.mtimeMs < cutoff) {
        await unlink(filePath);
        removed += 1;
      }
    }
    return removed;
  }

  async rotateActiveLogs(files, now) {
    const archived = [];
    const suffix = `.rotated-${rotationTimestamp(now)}`;
    try {
      await this.supervisor.restartWith(async () => {
        for (const file of files) {
          const archivePath = `${file.path}${suffix}`;
          await rename(file.path, archivePath);
          archived.push({ ...file, archivePath });
          await utimes(archivePath, now, now);
        }
      });
    } catch (error) {
      const rollbackErrors = [];
      for (const file of archived.reverse()) {
        try {
          await rename(file.archivePath, file.path);
        } catch (rollbackError) {
          rollbackErrors.push(rollbackError);
        }
      }

      try {
        if (!this.supervisor.child) await this.supervisor.start();
      } catch (restartError) {
        rollbackErrors.push(restartError);
      }
      if (rollbackErrors.length) {
        throw new AggregateError(
          [error, ...rollbackErrors],
          "Snort log rotation failed and rollback was incomplete.",
        );
      }
      throw error;
    }
  }

  async run(now = new Date()) {
    if (this.stopping) return { rotated: false, removed: 0 };
    if (this.currentRun) return this.currentRun;

    const task = this.runOnce(now);
    this.currentRun = task;
    try {
      return await task;
    } finally {
      if (this.currentRun === task) this.currentRun = null;
    }
  }

  async runOnce(now) {
    const removed = await this.pruneArchives(now);
    const files = await regularLogFiles(this.directory);
    if (files.length === 0) return { rotated: false, removed };

    const startOfDay = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()),
    ).getTime();
    const dailyRotationDue = files.some((file) => file.stats.mtimeMs < startOfDay);
    const sizeRotationDue = files.some(
      (file) => file.stats.size >= this.rotateSizeBytes,
    );
    if (!dailyRotationDue && !sizeRotationDue) {
      return { rotated: false, removed };
    }

    await this.rotateActiveLogs(files, now);
    return { rotated: true, removed };
  }

  async stop() {
    this.stopping = true;
    if (this.currentRun) await this.currentRun;
  }
}
