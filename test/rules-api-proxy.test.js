import assert from "node:assert/strict";
import { createServer, request } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { proxyRulesApi } from "../server/rules-api-proxy.mjs";

function listen(server, ...args) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(...args, resolve);
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

function sendRequest(port, route, options = {}, body = "") {
  return new Promise((resolve, reject) => {
    const requestToProxy = request(
      { host: "127.0.0.1", port, path: route, ...options },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => resolve({
          status: response.statusCode,
          headers: response.headers,
          body: Buffer.concat(chunks).toString("utf8"),
        }));
      },
    );
    requestToProxy.once("error", reject);
    requestToProxy.end(body);
  });
}

test("proxies rule updates over the private socket with the browser origin", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "snort-watch-proxy-"));
  const socketPath = path.join(directory, "rules.sock");
  let upstreamRequest;
  const upstream = createServer((requestFromConsole, response) => {
    const chunks = [];
    requestFromConsole.on("data", (chunk) => chunks.push(chunk));
    requestFromConsole.on("end", () => {
      upstreamRequest = {
        method: requestFromConsole.method,
        url: requestFromConsole.url,
        origin: requestFromConsole.headers.origin,
        body: Buffer.concat(chunks).toString("utf8"),
      };
      response.writeHead(200, {
        "content-type": "application/json",
        "cache-control": "no-store",
      });
      response.end(JSON.stringify({ saved: true }));
    });
  });
  const proxy = createServer((incoming, response) => {
    proxyRulesApi(
      incoming,
      response,
      new URL(incoming.url, "http://127.0.0.1"),
      socketPath,
    );
  });

  try {
    await listen(upstream, socketPath);
    await listen(proxy, 0, "127.0.0.1");
    const { port } = proxy.address();
    const result = await sendRequest(
      port,
      "/rules-api/api/rules?revision=abc",
      {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          origin: "http://127.0.0.1:3100",
        },
      },
      '{"content":"alert icmp any any -> any any (msg:\\"test\\")"}',
    );

    assert.equal(result.status, 200);
    assert.deepEqual(JSON.parse(result.body), { saved: true });
    assert.equal(result.headers["cache-control"], "no-store");
    assert.deepEqual(upstreamRequest, {
      method: "PUT",
      url: "/api/rules?revision=abc",
      origin: "http://127.0.0.1:3100",
      body: '{"content":"alert icmp any any -> any any (msg:\\"test\\")"}',
    });
  } finally {
    await close(proxy);
    await close(upstream);
    await rm(directory, { recursive: true, force: true });
  }
});

test("rejects paths outside the rule-management API", async () => {
  const proxy = createServer((requestFromClient, response) => {
    proxyRulesApi(
      requestFromClient,
      response,
      new URL(requestFromClient.url, "http://127.0.0.1"),
      "/unused/rules.sock",
    );
  });
  await listen(proxy, 0, "127.0.0.1");
  try {
    const result = await sendRequest(proxy.address().port, "/rules-api/api/other");
    assert.equal(result.status, 404);
    assert.deepEqual(JSON.parse(result.body), { error: "Rule API route not found." });
  } finally {
    await close(proxy);
  }
});
