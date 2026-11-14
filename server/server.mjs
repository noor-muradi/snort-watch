import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { readAlertRecords } from "./alerts-file.mjs";
import { aggregateAlertLocations, createGeoIpService } from "./geoip.mjs";
import { proxyRulesApi } from "./rules-api-proxy.mjs";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dataPath = path.resolve(
  process.env.SNORT_JSON_LOG ?? path.join(projectRoot, "data", "alerts.jsonl"),
);
const distPath = path.join(projectRoot, "dist");
const port = Number(process.env.PORT ?? 3100);
const host = process.env.HOST ?? "127.0.0.1";
const rulesApiSocket = process.env.RULES_API_SOCKET;
const geoIpService = createGeoIpService({
  databasePath:
    process.env.MAXMIND_DATABASE_PATH ??
    path.join(projectRoot, "data", "GeoLite2-City.mmdb"),
  accountId: process.env.MAXMIND_ACCOUNT_ID,
  licenseKey: process.env.MAXMIND_LICENSE_KEY,
});
let geoAlertsCache = null;
const mimeTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
};

function sendJson(response, status, payload) {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  response.end(JSON.stringify(payload));
}

async function serveAlerts(response) {
  try {
    const { alerts, malformedLines } = await readAlertRecords(dataPath);
    sendJson(response, 200, {
      alerts: alerts.reverse(),
      source: dataPath,
      loaded: alerts.length,
      malformedLines,
      truncated: false,
      updatedAt: new Date().toISOString(),
    });
  } catch (error) {
    sendJson(response, 503, {
      error: `Cannot read Snort JSON log at ${dataPath}: ${error.message}`,
      source: dataPath,
    });
  }
}

async function serveGeoAlerts(response) {
  const { reader, state, lastUpdated, updateError } = geoIpService.getStatus();
  if (!reader) {
    sendJson(response, 503, {
      error: updateError || "MaxMind GeoLite2 City database is unavailable.",
      state,
    });
    return;
  }

  try {
    const fileStat = await stat(dataPath);
    const cacheKey = `${fileStat.mtimeMs}:${fileStat.size}:${geoIpService.getStatus().version}`;
    if (!geoAlertsCache || geoAlertsCache.key !== cacheKey) {
      const { alerts } = await readAlertRecords(dataPath);
      geoAlertsCache = {
        key: cacheKey,
        ...aggregateAlertLocations(alerts, reader),
        alertCount: alerts.length,
      };
    }
    sendJson(response, 200, {
      locations: geoAlertsCache.locations,
      unmappedAddresses: geoAlertsCache.unmappedAddresses,
      alertCount: geoAlertsCache.alertCount,
      databaseUpdatedAt: lastUpdated,
    });
  } catch (error) {
    sendJson(response, 503, {
      error: `Cannot build IP geolocation summary: ${error.message}`,
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
  if (url.pathname.startsWith("/rules-api/")) {
    proxyRulesApi(request, response, url, rulesApiSocket);
    return;
  }
  if (request.method !== "GET") {
    sendJson(response, 405, { error: "Only GET requests are supported." });
    return;
  }

  if (url.pathname === "/api/health") {
    sendJson(response, 200, { status: "ok", source: dataPath });
  } else if (url.pathname === "/api/alerts") {
    void serveAlerts(response);
  } else if (url.pathname === "/api/geo/alerts") {
    void serveGeoAlerts(response);
  } else if (url.pathname.startsWith("/api/")) {
    sendJson(response, 404, { error: "API route not found." });
  } else {
    void serveStatic(response, url.pathname);
  }
});

server.listen(port, host, () => {
  console.info(`Snort Watch API listening on http://${host}:${port}`);
  console.info(`Reading JSON alerts from ${dataPath}`);
  void geoIpService.start().catch((error) =>
    console.error(`MaxMind geolocation initialization failed: ${error.message}`),
  );
});

process.on("SIGTERM", () => {
  geoIpService.stop();
  server.close(() => process.exit(0));
});

process.on("SIGINT", () => {
  geoIpService.stop();
  server.close(() => process.exit(0));
});
