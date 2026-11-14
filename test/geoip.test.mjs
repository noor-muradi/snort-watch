import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { c as createTar } from "tar";
import {
  aggregateAlertLocations,
  createGeoIpService,
} from "../server/geoip.mjs";

test("counts each public IP once per alert and excludes unmapped locations", () => {
  const alerts = [
    { source_ip: "8.8.8.8", destination_ip: "1.1.1.1" },
    { source_ip: "8.8.8.8", destination_ip: "8.8.8.8" },
    { source_ip: "192.168.1.5", destination_ip: "203.0.113.10" },
    { source_ip: "2001:4860:4860::8888", destination_ip: "invalid" },
  ];
  const lookedUp = [];
  const summary = aggregateAlertLocations(alerts, {
    get(address) {
      lookedUp.push(address);
      if (address === "1.1.1.1") {
        return { location: { latitude: -33.9, longitude: 151.2 } };
      }
      if (address === "8.8.8.8") {
        return { location: { latitude: 37.4, longitude: -122.1 } };
      }
      return null;
    },
  });

  assert.deepEqual(lookedUp, ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"]);
  assert.deepEqual(summary.locations, [
    { latitude: 37.4, longitude: -122.1, count: 2, city: null, country: null },
    { latitude: -33.9, longitude: 151.2, count: 1, city: null, country: null },
  ]);
  assert.equal(summary.unmappedAddresses, 1);
});

test("downloads and opens the MaxMind database during service startup", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "snort-watch-geoip-"));
  const archiveRoot = path.join(root, "archive-source");
  const archiveDirectory = path.join(archiveRoot, "GeoLite2-City_test");
  const archivePath = path.join(root, "database.tar.gz");
  const databasePath = path.join(root, "persistent", "GeoLite2-City.mmdb");
  await mkdir(archiveDirectory, { recursive: true });
  await writeFile(path.join(archiveDirectory, "GeoLite2-City.mmdb"), "test database");
  await createTar(
    { cwd: archiveRoot, file: archivePath, gzip: true },
    ["GeoLite2-City_test/GeoLite2-City.mmdb"],
  );
  const archive = await readFile(archivePath);
  const warnings = [];
  let fetchOptions;
  const service = createGeoIpService({
    databasePath,
    accountId: "12345",
    licenseKey: "test-license",
    fetchImpl: async (url, options) => {
      assert.match(url, /GeoLite2-City\/download\?suffix=tar\.gz$/);
      fetchOptions = options;
      return new Response(archive);
    },
    openDatabase: async (filePath) => {
      assert.equal(await readFile(filePath, "utf8"), "test database");
      return { get: () => null };
    },
    logger: { warn: (message) => warnings.push(message) },
  });

  try {
    await service.start();
    const status = service.getStatus();
    assert.equal(status.state, "ready");
    assert.equal(status.version, 1);
    assert.ok(status.lastUpdated);
    assert.equal(
      fetchOptions.headers.authorization,
      `Basic ${Buffer.from("12345:test-license").toString("base64")}`,
    );
    assert.equal(await readFile(databasePath, "utf8"), "test database");
    assert.deepEqual(warnings, []);
  } finally {
    service.stop();
    await rm(root, { recursive: true, force: true });
  }
});

test("keeps geolocation optional when credentials are not configured", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "snort-watch-geoip-"));
  const service = createGeoIpService({
    databasePath: path.join(root, "GeoLite2-City.mmdb"),
    fetchImpl: async () => {
      throw new Error("Should not attempt a download");
    },
    logger: { warn() {} },
  });

  try {
    await service.start();
    assert.equal(service.getStatus().state, "credentials_required");
    assert.equal(service.getStatus().reader, null);
  } finally {
    service.stop();
    await rm(root, { recursive: true, force: true });
  }
});
