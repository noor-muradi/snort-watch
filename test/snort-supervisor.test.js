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

test("reports an unexpected Snort process exit", async () => {
  let exitError;
  const supervisor = new SnortSupervisor({
    command: process.execPath,
    args: ["-e", "process.exit(3)"],
    onUnexpectedExit: (error) => {
      exitError = error;
    },
  });

  await supervisor.start();
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.match(exitError?.message ?? "", /exited unexpectedly.*code 3/);
});
