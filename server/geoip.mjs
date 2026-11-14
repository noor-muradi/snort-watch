import { createWriteStream } from "node:fs";
import { mkdtemp, mkdir, rename, rm, stat } from "node:fs/promises";
import path from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { x as extractTar } from "tar";
import maxmind from "maxmind";
import ipaddr from "ipaddr.js";

const DATABASE_NAME = "GeoLite2-City.mmdb";
const DOWNLOAD_URL =
  "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz";
const MAX_ARCHIVE_BYTES = 256 * 1024 * 1024;
const DEFAULT_REFRESH_INTERVAL = 7 * 24 * 60 * 60 * 1000;

export function aggregateAlertLocations(alerts, reader) {
  const counts = new Map();
  for (const alert of alerts) {
    const addresses = new Set([alert.source_ip, alert.destination_ip]);
    for (const address of addresses) {
      if (typeof address !== "string" || !address) continue;
      try {
        if (ipaddr.parse(address).range() !== "unicast") continue;
      } catch {
        continue;
      }
      counts.set(address, (counts.get(address) ?? 0) + 1);
    }
  }

  const locations = [];
  let unmappedAddresses = 0;
  for (const [address, count] of counts) {
    const record = reader.get(address);
    const latitude = record?.location?.latitude;
    const longitude = record?.location?.longitude;
    if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
      unmappedAddresses += 1;
      continue;
    }
    locations.push({
      latitude,
      longitude,
      count,
      city: record.city?.names?.en ?? null,
      country: record.country?.iso_code ?? null,
    });
  }
  return { locations, unmappedAddresses };
}

export function createGeoIpService({
  databasePath,
  accountId = "",
  licenseKey = "",
  fetchImpl = fetch,
  openDatabase = (filePath) => maxmind.open(filePath),
  refreshIntervalMs = DEFAULT_REFRESH_INTERVAL,
  logger = console,
}) {
  let reader = null;
  let state = "not_initialized";
  let lastUpdated = null;
  let updateError = "";
  let refreshPromise = null;
  let refreshTimer = null;
  let version = 0;

  async function loadExistingDatabase() {
    try {
      const databaseStat = await stat(databasePath);
      reader = await openDatabase(databasePath);
      version += 1;
      state = "ready";
      lastUpdated = databaseStat.mtime.toISOString();
      return true;
    } catch (error) {
      if (error.code !== "ENOENT") {
        logger.warn(`Cannot open existing MaxMind database: ${error.message}`);
      }
      return false;
    }
  }

  async function refresh() {
    if (refreshPromise) return refreshPromise;
    if (!accountId || !licenseKey) {
      state = reader ? "ready" : "credentials_required";
      return;
    }

    refreshPromise = (async () => {
      const directory = path.dirname(databasePath);
      let temporaryDirectory;
      try {
        temporaryDirectory = await mkdtemp(path.join(directory, ".maxmind-update-"));
        const archivePath = path.join(temporaryDirectory, "GeoLite2-City.tar.gz");
        const credentials = Buffer.from(`${accountId}:${licenseKey}`).toString("base64");
        const response = await fetchImpl(DOWNLOAD_URL, {
          headers: { authorization: `Basic ${credentials}` },
          signal: AbortSignal.timeout(30_000),
        });
        if (!response.ok || !response.body) {
          throw new Error(`MaxMind download failed with HTTP ${response.status}`);
        }

        let receivedBytes = 0;
        const byteLimit = new Transform({
          transform(chunk, encoding, callback) {
            receivedBytes += chunk.length;
            if (receivedBytes > MAX_ARCHIVE_BYTES) {
              callback(new Error("MaxMind database archive exceeds 256 MiB"));
              return;
            }
            callback(null, chunk);
          },
        });
        await pipeline(
          Readable.fromWeb(response.body),
          byteLimit,
          createWriteStream(archivePath, { mode: 0o600 }),
        );

        await mkdir(path.join(temporaryDirectory, "extracted"));
        await extractTar({
          file: archivePath,
          cwd: path.join(temporaryDirectory, "extracted"),
          strip: 1,
          filter: (entryPath) =>
            /^GeoLite2-City_[^/]+\/GeoLite2-City\.mmdb$/.test(entryPath),
        });
        const extractedPath = path.join(
          temporaryDirectory,
          "extracted",
          DATABASE_NAME,
        );
        const downloadedReader = await openDatabase(extractedPath);
        await rename(extractedPath, databasePath);
        reader = downloadedReader;
        version += 1;
        state = "ready";
        lastUpdated = new Date().toISOString();
        updateError = "";
      } catch (error) {
        updateError = error.message;
        state = reader ? "ready" : "unavailable";
        throw error;
      } finally {
        if (temporaryDirectory) {
          await rm(temporaryDirectory, { recursive: true, force: true });
        }
        refreshPromise = null;
      }
    })();

    return refreshPromise;
  }

  async function start() {
    await mkdir(path.dirname(databasePath), { recursive: true });
    await loadExistingDatabase();
    try {
      await refresh();
    } catch (error) {
      logger.warn(`MaxMind database update failed: ${error.message}`);
    }
    if (accountId && licenseKey) {
      refreshTimer = setInterval(() => {
        void refresh().catch((error) =>
          logger.warn(`MaxMind database update failed: ${error.message}`),
        );
      }, refreshIntervalMs);
      refreshTimer.unref();
    }
  }

  function getStatus() {
    return {
      state,
      lastUpdated,
      updateError,
      version,
      reader,
    };
  }

  function stop() {
    if (refreshTimer) clearInterval(refreshTimer);
  }

  return { start, refresh, getStatus, stop };
}
