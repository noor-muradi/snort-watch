import { createHash, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import {
  chmod,
  open,
  readFile,
  rename,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
const rulesPath = path.resolve(
  process.env.SNORT_MANAGED_RULES ??
    "/var/lib/snort-watch/ui-managed.rules",
);
const configPath = path.resolve(
  process.env.SNORT_CONFIG ?? "/etc/snort/snort.conf",
);
const snortBinary = process.env.SNORT_BIN ?? "/usr/sbin/snort";
const serviceName = process.env.SNORT_SERVICE ?? "snort";
const managedDirectory = path.dirname(rulesPath);
const communityActivePath = path.resolve(
  process.env.SNORT_COMMUNITY_RULES ??
    path.join(managedDirectory, "community-active.rules"),
);
const communityDownloadPath = path.resolve(
  process.env.SNORT_COMMUNITY_DOWNLOAD ??
    path.join(managedDirectory, "community-download.rules"),
);
const communityStatePath = path.resolve(
  process.env.SNORT_COMMUNITY_STATE ??
    path.join(managedDirectory, "community-state.json"),
);
const communityLicensePath = path.resolve(
  process.env.SNORT_COMMUNITY_LICENSE ??
    path.join(managedDirectory, "community-license.txt"),
);
const communityAuthorsPath = path.resolve(
  process.env.SNORT_COMMUNITY_AUTHORS ??
    path.join(managedDirectory, "community-authors.txt"),
);
const host = process.env.RULES_API_HOST ?? "127.0.0.1";
const port = Number(process.env.RULES_API_PORT ?? 3101);
const maxRequestBytes = 128 * 1024;
const maxCommunityArchiveBytes = 25 * 1024 * 1024;
const maxCommunityRulesBytes = 5 * 1024 * 1024;
const communityArchiveUrl =
  "https://www.snort.org/downloads/community/community-rules.tar.gz";
const communitySourceUrl =
  "https://www.snort.org/downloads/#rule-downloads";
const emptyCommunityRules =
  "# Snort Watch managed GPLv2 community rules. Install from the Rules UI.\n";
const communityArchiveHosts = new Set([
  "www.snort.org",
  "snort-org-site.s3.amazonaws.com",
]);
const allowedOrigins = new Set(
  (
    process.env.RULES_ALLOWED_ORIGINS ??
    "http://127.0.0.1:3100,http://localhost:3100,http://127.0.0.1:5173,http://localhost:5173"
  )
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean),
);

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("RULES_API_PORT must be a valid TCP port.");
}
if (!path.isAbsolute(rulesPath) || !path.isAbsolute(configPath)) {
  throw new Error("Snort rules and config paths must be absolute.");
}
if (
  [
    communityActivePath,
    communityDownloadPath,
    communityStatePath,
    communityLicensePath,
    communityAuthorsPath,
  ].some((filePath) => path.dirname(filePath) !== managedDirectory)
) {
  throw new Error("Community rules files must be inside the managed rules directory.");
}
if (!/^[a-zA-Z0-9_.@-]+$/.test(serviceName)) {
  throw new Error("SNORT_SERVICE must be a systemd unit name.");
}

export function validateRuleContent(content) {
  if (typeof content !== "string") {
    return ["Rules content must be a string."];
  }
  if (Buffer.byteLength(content, "utf8") > maxRequestBytes) {
    return ["Rules file must be 128 KiB or smaller."];
  }
  if (content.includes("\0")) {
    return ["Rules content cannot contain NUL characters."];
  }

  const lines = content.replace(/\r\n/g, "\n").split("\n");
  if (lines.length > 501) {
    return ["Rules file must contain at most 500 rule lines."];
  }

  const errors = [];
  for (const [index, rawLine] of lines.entries()) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    if (!line.startsWith("alert ")) {
      errors.push(
        `Line ${index + 1}: only Snort alert rules are allowed; directives and other actions are not supported.`,
      );
      continue;
    }

    if (
      !/^alert\s+\S+\s+\S+\s+\S+\s+(?:->|<>)\s+\S+\s+\S+\s+\(.+\)\s*$/.test(
        line,
      )
    ) {
      errors.push(
        `Line ${index + 1}: expected a complete single-line Snort alert rule.`,
      );
    }
  }

  return errors;
}

export function validateCommunityRuleFile(content) {
  if (typeof content !== "string") {
    return { errors: ["Community rules content must be text."], ruleCount: 0 };
  }
  if (Buffer.byteLength(content, "utf8") > maxCommunityRulesBytes) {
    return { errors: ["Community rules file exceeds the 5 MiB limit."], ruleCount: 0 };
  }
  if (content.includes("\0")) {
    return { errors: ["Community rules cannot contain NUL characters."], ruleCount: 0 };
  }
  if (!/GNU General Public License \(GPL\)[\s\S]*?\bv2\b/.test(content)) {
    return {
      errors: ["The official community rules file does not identify its GPLv2 license."],
      ruleCount: 0,
    };
  }

  const errors = [];
  let ruleCount = 0;
  for (const [index, rawLine] of content.replace(/\r\n/g, "\n").split("\n").entries()) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    if (!line.startsWith("alert ")) {
      errors.push(`Line ${index + 1}: only alert rules and comments are allowed.`);
      continue;
    }
    if (
      !/^alert\s+\S+\s+\S+\s+\S+\s+(?:->|<>)\s+\S+\s+\S+\s+\(.+\)\s*$/.test(
        line,
      )
    ) {
      errors.push(`Line ${index + 1}: expected a complete single-line alert rule.`);
      continue;
    }
    ruleCount += 1;
  }
  if (ruleCount === 0) {
    errors.push("Community rules file contains no active alert rules.");
  }
  return { errors, ruleCount };
}

export function validateCommunityArchiveMembers(members) {
  if (!Array.isArray(members)) {
    return ["Community archive member list is invalid."];
  }
  if (
    members.some(
      (member) =>
        typeof member !== "string" ||
        member.startsWith("/") ||
        member.includes("\\") ||
        member.split("/").includes(".."),
    )
  ) {
    return ["Community archive contains an unsafe member path."];
  }
  if (
    members.filter((member) => member === "community-rules/community.rules").length !== 1 ||
    members.filter((member) => member === "community-rules/LICENSE").length !== 1 ||
    members.filter((member) => member === "community-rules/AUTHORS").length !== 1
  ) {
    return ["Official archive is missing expected community rules, license, or AUTHORS files."];
  }
  return [];
}

function revisionFor(content) {
  return `sha256-${createHash("sha256").update(content).digest("hex")}`;
}

async function writeTextAtomically(targetPath, content) {
  const temporaryPath = `${targetPath}.${randomUUID()}.tmp`;
  let temporaryCreated = false;
  try {
    const handle = await open(temporaryPath, "wx", 0o640);
    temporaryCreated = true;
    try {
      await handle.writeFile(content, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    await chmod(temporaryPath, 0o640);
    await rename(temporaryPath, targetPath);
    temporaryCreated = false;
  } finally {
    if (temporaryCreated) {
      await unlink(temporaryPath).catch((error) => {
        if (error.code !== "ENOENT") {
          throw error;
        }
      });
    }
  }
}

async function snapshotFiles(paths) {
  return new Map(
    await Promise.all(
      paths.map(async (filePath) => {
        try {
          return [filePath, await readFile(filePath)];
        } catch (error) {
          if (error.code === "ENOENT") return [filePath, null];
          throw error;
        }
      }),
    ),
  );
}

async function restoreFiles(snapshot) {
  for (const [filePath, content] of snapshot) {
    if (content === null) {
      await unlink(filePath).catch((error) => {
        if (error.code !== "ENOENT") throw error;
      });
    } else {
      await writeTextAtomically(filePath, content);
    }
  }
}

async function writeAtomically(content) {
  return writeTextAtomically(rulesPath, content);
}

async function downloadCommunityArchive() {
  let url = new URL(communityArchiveUrl);
  let response;
  for (let redirects = 0; redirects <= 5; redirects += 1) {
    if (url.protocol !== "https:" || !communityArchiveHosts.has(url.hostname)) {
      throw new Error("Community rules download redirected to an untrusted host.");
    }
    response = await fetch(url, {
      redirect: "manual",
      signal: AbortSignal.timeout(30_000),
      headers: { "user-agent": "Snort-Watch/1.0" },
    });
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      await response.body?.cancel();
      if (!location || redirects === 5) {
        throw new Error("Community rules download exceeded its redirect limit.");
      }
      url = new URL(location, url);
      continue;
    }
    break;
  }
  if (!response?.ok || !response.body) {
    throw new Error(
      `Official community rules download failed (${response?.status ?? "no response"}).`,
    );
  }

  const announcedSize = Number(response.headers.get("content-length"));
  if (Number.isFinite(announcedSize) && announcedSize > maxCommunityArchiveBytes) {
    await response.body.cancel();
    throw new Error("Official community rules archive exceeds the 25 MiB limit.");
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of response.body) {
    total += chunk.length;
    if (total > maxCommunityArchiveBytes) {
      throw new Error("Official community rules archive exceeds the 25 MiB limit.");
    }
    chunks.push(chunk);
  }
  return {
    archive: Buffer.concat(chunks),
    downloadedAt: new Date().toISOString(),
    etag: response.headers.get("etag"),
    lastModified: response.headers.get("last-modified"),
  };
}

async function extractCommunityPackage(archive) {
  const archivePath = `${communityActivePath}.${randomUUID()}.tar.gz`;
  try {
    await writeFile(archivePath, archive, { flag: "wx", mode: 0o600 });
    const [{ stdout: listing }, { stdout: verboseListing }] = await Promise.all([
      execFileAsync(
        "/usr/bin/tar",
        ["-tzf", archivePath],
        { timeout: 30_000, maxBuffer: 1024 * 1024 },
      ),
      execFileAsync(
        "/usr/bin/tar",
        ["-tvzf", archivePath],
        { timeout: 30_000, maxBuffer: 1024 * 1024 },
      ),
    ]);
    const members = listing.toString("utf8").split(/\r?\n/).filter(Boolean);
    const memberErrors = validateCommunityArchiveMembers(members);
    if (memberErrors.length) {
      throw new Error(memberErrors.join(" "));
    }
    if (
      verboseListing
        .toString("utf8")
        .split(/\r?\n/)
        .filter(Boolean)
        .some((entry) => !entry.startsWith("-") && !entry.startsWith("d"))
    ) {
      throw new Error("Official archive contains a non-regular file or directory.");
    }

    const [rulesResult, licenseResult, authorsResult] = await Promise.all([
      execFileAsync(
        "/usr/bin/tar",
        ["-xOzf", archivePath, "community-rules/community.rules"],
        { timeout: 60_000, maxBuffer: maxCommunityRulesBytes + 1 },
      ),
      execFileAsync(
        "/usr/bin/tar",
        ["-xOzf", archivePath, "community-rules/LICENSE"],
        { timeout: 30_000, maxBuffer: 128 * 1024 },
      ),
      execFileAsync(
        "/usr/bin/tar",
        ["-xOzf", archivePath, "community-rules/AUTHORS"],
        { timeout: 30_000, maxBuffer: 256 * 1024 },
      ),
    ]);
    const rules = rulesResult.stdout.toString("utf8");
    const license = licenseResult.stdout.toString("utf8");
    const authors = authorsResult.stdout.toString("utf8");
    const validation = validateCommunityRuleFile(rules);
    if (validation.errors.length) {
      throw new Error(`Official community rules failed validation: ${validation.errors.join(" ")}`);
    }
    if (!/GNU General Public License/i.test(license) || !/\bversion 2\b/i.test(license)) {
      throw new Error("Official community archive does not include the expected GPLv2 license.");
    }
    if (!authors.trim() || authors.includes("\0")) {
      throw new Error("Official community archive contains invalid AUTHORS metadata.");
    }
    return { rules, license, authors, ruleCount: validation.ruleCount };
  } finally {
    await unlink(archivePath).catch((error) => {
      if (error.code !== "ENOENT") throw error;
    });
  }
}

async function readCommunityStatus() {
  const [active, downloaded, stateContent] = await Promise.all([
    readFile(communityActivePath, "utf8"),
    readFile(communityDownloadPath, "utf8").catch((error) => {
      if (error.code === "ENOENT") return "";
      throw error;
    }),
    readFile(communityStatePath, "utf8").catch((error) => {
      if (error.code === "ENOENT") return "{}";
      throw error;
    }),
  ]);
  let state;
  try {
    state = JSON.parse(stateContent);
  } catch {
    throw new Error("Community rules state file is invalid JSON.");
  }
  const activeCount = active
    .split(/\r?\n/)
    .filter((line) => line.trim().startsWith("alert ")).length;
  const downloadedCount = downloaded
    .split(/\r?\n/)
    .filter((line) => line.trim().startsWith("alert ")).length;
  return {
    installed: downloadedCount > 0,
    enabled: Boolean(state.enabled) && activeCount > 0,
    activeRuleCount: activeCount,
    downloadedRuleCount: downloadedCount,
    downloadedAt: state.downloadedAt ?? null,
    checksum: state.checksum ?? null,
    source: communityArchiveUrl,
    sourcePage: communitySourceUrl,
    license: "GNU GPLv2",
    licenseFile: communityLicensePath,
    authorsFile: communityAuthorsPath,
    authorCount: state.authorCount ?? null,
    service: serviceName,
  };
}

async function runPrivileged(command, args) {
  try {
    const result = await execFileAsync(
      "/usr/bin/sudo",
      ["-n", command, ...args],
      { timeout: 60_000, maxBuffer: 1024 * 1024 },
    );
    return {
      ok: true,
      output: `${result.stdout ?? ""}${result.stderr ?? ""}`.trim(),
    };
  } catch (error) {
    return {
      ok: false,
      output: `${error.stdout ?? ""}${error.stderr ?? ""}`.trim(),
      message: error.message,
    };
  }
}

async function getRules() {
  const [content, fileStat] = await Promise.all([
    readFile(rulesPath, "utf8"),
    stat(rulesPath),
  ]);
  if (!fileStat.isFile()) {
    throw new Error("Managed rules path is not a regular file.");
  }

  return {
    content,
    revision: revisionFor(content),
    ruleCount: content
      .split(/\r?\n/)
      .filter((line) => line.trim().startsWith("alert ")).length,
    file: rulesPath,
    service: serviceName,
  };
}

function sendJson(response, status, payload, origin) {
  const headers = {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  };
  if (origin && allowedOrigins.has(origin)) {
    headers["access-control-allow-origin"] = origin;
    headers["access-control-allow-methods"] = "GET, PUT, POST, OPTIONS";
    headers["access-control-allow-headers"] = "content-type, if-match";
    headers.vary = "Origin";
  }
  response.writeHead(status, headers);
  response.end(JSON.stringify(payload));
}

async function readRequestBody(request) {
  let size = 0;
  const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxRequestBytes) {
      const error = new Error("Request body exceeds 128 KiB.");
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }

  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    const error = new Error("Request body must be valid JSON.");
    error.statusCode = 400;
    throw error;
  }
}

let applyingRules = false;

async function updateRules(response, request, origin) {
  if (!origin || !allowedOrigins.has(origin)) {
    sendJson(response, 403, { error: "Rule changes require an approved local UI origin." }, origin);
    return;
  }
  if (!request.headers["content-type"]?.startsWith("application/json")) {
    sendJson(response, 415, { error: "Content-Type must be application/json." }, origin);
    return;
  }
  if (applyingRules) {
    sendJson(response, 409, { error: "Another rule update is in progress." }, origin);
    return;
  }

  applyingRules = true;
  try {
    const body = await readRequestBody(request);
    const errors = validateRuleContent(body?.content);
    if (errors.length) {
      sendJson(response, 422, { error: errors.join("\n"), validationErrors: errors }, origin);
      return;
    }

    const current = await getRules();
    if (body.expectedRevision !== current.revision) {
      sendJson(response, 409, {
        error: "Rules changed since they were loaded. Reload before applying your edits.",
        revision: current.revision,
      }, origin);
      return;
    }

    const newContent = body.content.replace(/\r\n/g, "\n");
    if (newContent === current.content) {
      sendJson(response, 200, {
        ...current,
        message: "No changes to apply.",
        restarted: false,
      }, origin);
      return;
    }

    await writeAtomically(newContent);
    const validation = await runPrivileged(snortBinary, [
      "-T",
      "-c",
      configPath,
    ]);
    if (!validation.ok) {
      await writeAtomically(current.content);
      sendJson(response, 422, {
        error: "Snort rejected the rules. The previous rules were restored.",
        details: validation.output || validation.message,
      }, origin);
      return;
    }

    const restart = await runPrivileged("/usr/bin/systemctl", [
      "restart",
      serviceName,
    ]);
    if (!restart.ok) {
      await writeAtomically(current.content);
      const rollbackRestart = await runPrivileged("/usr/bin/systemctl", [
        "restart",
        serviceName,
      ]);
      sendJson(response, 503, {
        error: "Snort could not restart with the new rules. The previous rules were restored.",
        details: restart.output || restart.message,
        rollback: rollbackRestart.ok
          ? "Previous rules restored and Snort restart requested."
          : `Previous rules restored, but service restart also failed: ${rollbackRestart.output || rollbackRestart.message}`,
      }, origin);
      return;
    }

    const result = await getRules();
    sendJson(response, 200, {
      ...result,
      message: "Rules validated and applied. Snort has restarted.",
      restarted: true,
    }, origin);
  } catch (error) {
    const status = error.statusCode ?? 500;
    sendJson(response, status, { error: error.message }, origin);
  } finally {
    applyingRules = false;
  }
}

async function updateCommunityRules(response, request, origin) {
  if (!origin || !allowedOrigins.has(origin)) {
    sendJson(response, 403, { error: "Community rule changes require an approved local UI origin." }, origin);
    return;
  }
  if (!request.headers["content-type"]?.startsWith("application/json")) {
    sendJson(response, 415, { error: "Content-Type must be application/json." }, origin);
    return;
  }
  if (applyingRules) {
    sendJson(response, 409, { error: "Another rule update is in progress." }, origin);
    return;
  }

  applyingRules = true;
  let snapshot;
  let filesMutated = false;
  try {
    const body = await readRequestBody(request);
    if (!["install", "update", "enable", "disable", "remove"].includes(body?.action)) {
      sendJson(response, 400, { error: "Choose install, update, enable, disable, or remove." }, origin);
      return;
    }

    const paths = [
      communityActivePath,
      communityDownloadPath,
      communityStatePath,
      communityLicensePath,
      communityAuthorsPath,
    ];
    snapshot = await snapshotFiles(paths);
    let active = emptyCommunityRules;
    let downloaded = snapshot.get(communityDownloadPath)?.toString("utf8") ?? "";
    let license = snapshot.get(communityLicensePath)?.toString("utf8") ?? "";
    let authors = snapshot.get(communityAuthorsPath)?.toString("utf8") ?? "";
    let state = {};
    try {
      const stateContent = snapshot.get(communityStatePath)?.toString("utf8");
      if (stateContent) state = JSON.parse(stateContent);
    } catch {
      sendJson(response, 500, { error: "Community rules state file is invalid JSON." }, origin);
      return;
    }

    if (body.action === "install" || body.action === "update") {
      const download = await downloadCommunityArchive();
      const packageContent = await extractCommunityPackage(download.archive);
      downloaded = packageContent.rules;
      license = `${packageContent.license}\n`;
      authors = `${packageContent.authors}\n`;
      const enabled = body.action === "install" || Boolean(state.enabled);
      active = enabled ? downloaded : emptyCommunityRules;
      state = {
        enabled,
        downloadedAt: download.downloadedAt,
        etag: download.etag,
        lastModified: download.lastModified,
        checksum: revisionFor(downloaded),
        ruleCount: packageContent.ruleCount,
        authorCount: packageContent.authors.split(/\r?\n/).filter(Boolean).length,
      };
    } else if (body.action === "enable") {
      const validation = validateCommunityRuleFile(downloaded);
      if (validation.errors.length) {
        sendJson(response, 409, {
          error: "No valid downloaded community rules are available to enable.",
          details: validation.errors.join("\n"),
        }, origin);
        return;
      }
      active = downloaded;
      state = { ...state, enabled: true };
    } else if (body.action === "disable") {
      active = emptyCommunityRules;
      state = { ...state, enabled: false };
    } else {
      downloaded = "";
      license = "";
      authors = "";
      state = {};
    }

    await writeTextAtomically(communityActivePath, active);
    filesMutated = true;
    if (body.action === "remove") {
      for (const filePath of [
        communityDownloadPath,
        communityStatePath,
        communityLicensePath,
        communityAuthorsPath,
      ]) {
        await unlink(filePath).catch((error) => {
          if (error.code !== "ENOENT") throw error;
        });
      }
    } else {
      if (body.action === "install" || body.action === "update") {
        await writeTextAtomically(communityDownloadPath, downloaded);
        await writeTextAtomically(communityLicensePath, license);
        await writeTextAtomically(communityAuthorsPath, authors);
      }
      await writeTextAtomically(communityStatePath, `${JSON.stringify(state, null, 2)}\n`);
    }

    const updatedStatus = await readCommunityStatus();
    const validation = await runPrivileged(snortBinary, [
      "-T",
      "-c",
      configPath,
    ]);
    if (!validation.ok) {
      await restoreFiles(snapshot);
      sendJson(response, 422, {
        error: "Snort rejected the community rules. The previous files were restored.",
        details: validation.output || validation.message,
      }, origin);
      return;
    }

    const restart = await runPrivileged("/usr/bin/systemctl", [
      "restart",
      serviceName,
    ]);
    if (!restart.ok) {
      await restoreFiles(snapshot);
      const rollbackRestart = await runPrivileged("/usr/bin/systemctl", [
        "restart",
        serviceName,
      ]);
      sendJson(response, 503, {
        error: "Snort could not restart with the community rules. The previous files were restored.",
        details: restart.output || restart.message,
        rollback: rollbackRestart.ok
          ? "Previous rules restored and Snort restart requested."
          : `Previous rules restored, but service restart also failed: ${rollbackRestart.output || rollbackRestart.message}`,
      }, origin);
      return;
    }

    sendJson(response, 200, {
      ...updatedStatus,
      message: body.action === "install"
        ? "GPLv2 Community Rules installed, validated, and enabled."
        : body.action === "update"
          ? state.enabled
            ? "Community Rules updated, validated, and enabled."
            : "Community Rules updated; they remain disabled."
        : body.action === "enable"
          ? "Community Rules enabled, validated, and applied."
          : body.action === "disable"
            ? "Community Rules disabled; downloaded rules are retained."
            : "Community Rules removed and Snort restarted.",
      restarted: true,
    }, origin);
  } catch (error) {
    const status = error.statusCode ?? (error.message.includes("download") ? 502 : 500);
    let message = error.message;
    if (filesMutated && snapshot) {
      try {
        await restoreFiles(snapshot);
      } catch (rollbackError) {
        message += ` Filesystem rollback failed: ${rollbackError.message}`;
      }
    }
    sendJson(response, status, { error: message }, origin);
  } finally {
    applyingRules = false;
  }
}

const server = createServer(async (request, response) => {
  const origin = request.headers.origin;
  if (origin && !allowedOrigins.has(origin)) {
    sendJson(response, 403, { error: "Origin is not allowed." });
    return;
  }

  if (request.method === "OPTIONS") {
    if (!origin || !allowedOrigins.has(origin)) {
      sendJson(response, 403, { error: "Origin is not allowed." });
      return;
    }
    response.writeHead(204, {
      "access-control-allow-origin": origin,
      "access-control-allow-methods": "GET, PUT, POST, OPTIONS",
      "access-control-allow-headers": "content-type, if-match",
      "access-control-max-age": "600",
      vary: "Origin",
    });
    response.end();
    return;
  }

  const url = new URL(request.url ?? "/", `http://${host}:${port}`);
  if (url.pathname === "/api/community-rules" && request.method === "GET") {
    try {
      sendJson(response, 200, await readCommunityStatus(), origin);
    } catch (error) {
      sendJson(response, 503, { error: `Cannot read community rule status: ${error.message}` }, origin);
    }
    return;
  }
  if (url.pathname === "/api/community-rules" && request.method === "POST") {
    await updateCommunityRules(response, request, origin);
    return;
  }
  if (url.pathname !== "/api/rules") {
    sendJson(response, 404, { error: "Route not found." }, origin);
    return;
  }
  if (request.method === "GET") {
    try {
      sendJson(response, 200, await getRules(), origin);
    } catch (error) {
      sendJson(response, 503, { error: `Cannot read managed rules: ${error.message}` }, origin);
    }
    return;
  }
  if (request.method === "PUT") {
    await updateRules(response, request, origin);
    return;
  }
  sendJson(response, 405, { error: "Only GET and PUT are supported for custom rules." }, origin);
});

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  server.listen(port, host, () => {
    console.info(`Snort rule manager listening on http://${host}:${port}`);
    console.info(`Managing alert rules in ${rulesPath}`);
  });

  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => {
      server.close((error) => {
        if (error) {
          console.error("Could not close the Snort rule manager:", error);
          process.exitCode = 1;
        }
      });
    });
  }
}
