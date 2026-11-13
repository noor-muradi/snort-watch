import { spawn } from "node:child_process";

export class SnortSupervisor {
  constructor({ command, args, spawnProcess = spawn, onUnexpectedExit = () => {} }) {
    this.command = command;
    this.args = args;
    this.spawnProcess = spawnProcess;
    this.onUnexpectedExit = onUnexpectedExit;
    this.child = null;
    this.stopping = false;
    this.restarting = false;
  }

  start() {
    if (this.child) {
      throw new Error("Snort is already running.");
    }

    return new Promise((resolve, reject) => {
      const child = this.spawnProcess(this.command, this.args, { stdio: "inherit" });
      this.child = child;
      let started = false;
      child.once("spawn", () => {
        started = true;
        resolve({ ok: true, output: "Snort process started." });
      });
      child.once("error", (error) => {
        if (this.child === child) this.child = null;
        if (!started) {
          reject(error);
        } else {
          this.onUnexpectedExit(error);
        }
      });
      child.once("exit", (code, signal) => {
        if (this.child === child) this.child = null;
        if (!started) {
          reject(new Error(`Snort exited before starting (code ${code}, signal ${signal ?? "none"}).`));
        } else if (!this.stopping && !this.restarting) {
          this.onUnexpectedExit(new Error(`Snort exited unexpectedly (code ${code}, signal ${signal ?? "none"}).`));
        }
      });
    });
  }

  async stopChild() {
    const child = this.child;
    if (!child) return;

    await new Promise((resolve) => {
      const timeout = setTimeout(() => child.kill("SIGKILL"), 10_000);
      child.once("exit", () => {
        clearTimeout(timeout);
        resolve();
      });
      child.kill("SIGTERM");
    });
  }

  async restart() {
    return this.restartWith();
  }

  async restartWith(beforeStart = async () => {}) {
    this.restarting = true;
    try {
      await this.stopChild();
      await beforeStart();
      return await this.start();
    } finally {
      this.restarting = false;
    }
  }

  async stop() {
    this.stopping = true;
    await this.stopChild();
  }
}
