import { createReadStream } from "node:fs";
import { open, stat } from "node:fs/promises";
import { createServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dataPath = path.resolve(
  process.env.SNORT_JSON_LOG ?? path.join(projectRoot, "data", "alerts.jsonl"),
);
const distPath = path.join(projectRoot, "dist");
const port = Number(process.env.PORT ?? 3100);
const host = process.env.HOST ?? "127.0.0.1";
const maxBytes = 8 * 1024 * 1024;
const mimeTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
};

async function readRecentLines(filePath, maxLines) {
  const fileStat = await stat(filePath);
  if (!fileStat.isFile()) {
    throw new Error("The configured Snort JSON path is not a file.");
  }

  const start = Math.max(0, fileStat.size - maxBytes);
  const handle = await open(filePath, "r");
  try {
    const buffer = Buffer.alloc(fileStat.size - start);
    await handle.read(buffer, 0, buffer.length, start);
    const text = buffer.toString("utf8");
    const lines = text.split(/\r?\n/);
    if (start > 0) {
      lines.shift();
    }
    return {
      lines: lines.filter((line) => line.trim()).slice(-maxLines),
      truncated: start > 0,
    };
  } finally {
    await handle.close();
  }
}

function sendJson(response, status, payload) {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  response.end(JSON.stringify(payload));
}

async function serveAlerts(response, url) {
  const requestedLimit = Number(url.searchParams.get("limit") ?? 500);
  const limit = Number.isInteger(requestedLimit)
    ? Math.max(1, Math.min(requestedLimit, 2000))
    : 500;

  try {
    const { lines, truncated } = await readRecentLines(dataPath, limit);
    const alerts = [];
    let malformedLines = 0;

    for (const line of lines) {
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

    sendJson(response, 200, {
      alerts: alerts.reverse(),
      source: dataPath,
      loaded: alerts.length,
      malformedLines,
      truncated,
      updatedAt: new Date().toISOString(),
    });
  } catch (error) {
    sendJson(response, 503, {
      error: `Cannot read Snort JSON log at ${dataPath}: ${error.message}`,
      source: dataPath,
    });
  }
}

async function serveStatic(response, pathname) {
  let decodedPath;
  try {
    decodedPath = decodeURIComponent(pathname);
  } catch {
    response.writeHead(400).end("Bad request");
    return;
  }

  const relativePath = decodedPath === "/" ? "index.html" : decodedPath.slice(1);
  const filePath = path.resolve(distPath, relativePath);
  if (!filePath.startsWith(`${distPath}${path.sep}`) && filePath !== distPath) {
    response.writeHead(403).end("Forbidden");
    return;
  }

  try {
    const fileStat = await stat(filePath);
    if (!fileStat.isFile()) {
      throw new Error("Not a file");
    }
    response.writeHead(200, {
      "content-type": mimeTypes[path.extname(filePath)] ?? "application/octet-stream",
    });
    createReadStream(filePath).pipe(response);
  } catch {
    if (path.extname(relativePath)) {
      response.writeHead(404).end("Not found");
      return;
    }
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    createReadStream(path.join(distPath, "index.html")).pipe(response);
  }
}

const server = createServer((request, response) => {
  const url = new URL(request.url ?? "/", "http://127.0.0.1");
  if (request.method !== "GET") {
    sendJson(response, 405, { error: "Only GET requests are supported." });
    return;
  }

  if (url.pathname === "/api/health") {
    sendJson(response, 200, { status: "ok", source: dataPath });
  } else if (url.pathname === "/api/alerts") {
    void serveAlerts(response, url);
  } else if (url.pathname.startsWith("/api/")) {
    sendJson(response, 404, { error: "API route not found." });
  } else {
    void serveStatic(response, url.pathname);
  }
});

server.listen(port, host, () => {
  console.info(`Snort Watch API listening on http://${host}:${port}`);
  console.info(`Reading JSON alerts from ${dataPath}`);
});
