import assert from "node:assert/strict";
import test from "node:test";
import { SnortSupervisor } from "../server/snort-supervisor.mjs";

test("starts, restarts, and stops the supervised Snort process", async () => {
  const supervisor = new SnortSupervisor({
    command: process.execPath,
    args: ["-e", "setInterval(() => {}, 1000)"],
  });

  await supervisor.start();
  const firstPid = supervisor.child.pid;
  assert.ok(firstPid);

  await supervisor.restart();
  assert.ok(supervisor.child.pid);
  assert.notEqual(supervisor.child.pid, firstPid);

  await supervisor.stop();
  assert.equal(supervisor.child, null);
});

test("runs log rotation between stopping and restarting Snort", async () => {
  const supervisor = new SnortSupervisor({
    command: process.execPath,
    args: ["-e", "setInterval(() => {}, 1000)"],
  });
  const processStates = [];

  await supervisor.start();
  await supervisor.restartWith(async () => {
    processStates.push(supervisor.child);
  });

  assert.deepEqual(processStates, [null]);
  assert.ok(supervisor.child);
  await supervisor.stop();
});

test("reports an unexpected Snort process exit", async () => {
  let resolveExit;
  const unexpectedExit = new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error("Timed out waiting for Snort exit notification.")),
      3000,
    );
    resolveExit = (error) => {
      clearTimeout(timeout);
      resolve(error);
    };
  });
  const supervisor = new SnortSupervisor({
    command: process.execPath,
    args: ["-e", "process.exit(3)"],
    onUnexpectedExit: resolveExit,
  });

  await supervisor.start();
  const exitError = await unexpectedExit;
  assert.match(exitError.message, /exited unexpectedly.*code 3/);
});
