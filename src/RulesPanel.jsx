import { useCallback, useEffect, useState } from "react";
import { buildAlertRule } from "./rule-builder.js";
import { parseRuleSummaries } from "./rule-list.js";

const RULES_API_URL = import.meta.env.DEV
  ? "/rules-api/api/rules"
  : "http://127.0.0.1:3101/api/rules";
const COMMUNITY_API_URL = import.meta.env.DEV
  ? "/rules-api/api/community-rules"
  : "http://127.0.0.1:3101/api/community-rules";

async function readResponse(response) {
  const payload = await response.json();
  if (!response.ok) {
    const error = new Error(payload.error ?? `Request failed (${response.status})`);
    error.details = payload.details;
    error.rollback = payload.rollback;
    throw error;
  }
  return payload;
}

function RulesPanel() {
  const [content, setContent] = useState("");
  const [savedContent, setSavedContent] = useState("");
  const [revision, setRevision] = useState("");
  const [ruleCount, setRuleCount] = useState(0);
  const [file, setFile] = useState("");
  const [service, setService] = useState("snort");
  const [status, setStatus] = useState("loading");
  const [error, setError] = useState("");
  const [details, setDetails] = useState("");
  const [message, setMessage] = useState("");
  const [saving, setSaving] = useState(false);
  const [builderForm, setBuilderForm] = useState({
    message: "",
    protocol: "icmp",
    source: "any",
    sourcePort: "any",
    destination: "$HOME_NET",
    destinationPort: "any",
    direction: "->",
    priority: "2",
    icmpType: "8",
  });
  const [builderFeedback, setBuilderFeedback] = useState(null);
  const [community, setCommunity] = useState(null);
  const [communityError, setCommunityError] = useState("");
  const [communityDetails, setCommunityDetails] = useState("");
  const [communityMessage, setCommunityMessage] = useState("");
  const [communityAction, setCommunityAction] = useState("");

  const loadRules = useCallback(async () => {
    setStatus("loading");
    setError("");
    setDetails("");
    setMessage("");
    setBuilderFeedback(null);
    try {
      const payload = await readResponse(await fetch(RULES_API_URL));
      setContent(payload.content);
      setSavedContent(payload.content);
      setRevision(payload.revision);
      setRuleCount(payload.ruleCount);
      setFile(payload.file);
      setService(payload.service);
      setStatus("connected");
    } catch (loadError) {
      setStatus("error");
      setError(loadError.message);
    }
  }, []);

  useEffect(() => {
    void loadRules();
  }, [loadRules]);

  const loadCommunityRules = useCallback(async () => {
    setCommunityError("");
    try {
      setCommunity(await readResponse(await fetch(COMMUNITY_API_URL)));
    } catch (loadError) {
      setCommunityError(loadError.message);
    }
  }, []);

  useEffect(() => {
    void loadCommunityRules();
  }, [loadCommunityRules]);

  async function saveRules(nextContent, showBuilderFeedback = false) {
    setSaving(true);
    setError("");
    setDetails("");
    setMessage("");
    if (showBuilderFeedback) {
      setBuilderFeedback({ type: "pending", text: "Validating and applying rule…" });
    }

    try {
      const payload = await readResponse(
        await fetch(RULES_API_URL, {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ content: nextContent, expectedRevision: revision }),
        }),
      );
      setContent(payload.content);
      setSavedContent(payload.content);
      setRevision(payload.revision);
      setRuleCount(payload.ruleCount);
      setMessage(showBuilderFeedback ? "" : payload.message);
      setBuilderFeedback(showBuilderFeedback
        ? { type: "success", text: payload.message || "Rule applied successfully." }
        : null);
      setStatus("connected");
    } catch (saveError) {
      setError(saveError.message);
      setDetails(saveError.details ?? "");
      if (showBuilderFeedback) {
        setBuilderFeedback({ type: "error", text: saveError.message });
      }
      if (saveError.message.includes("Rules changed since they were loaded")) {
        setStatus("conflict");
      }
    } finally {
      setSaving(false);
    }
  }

  async function applyRules(event) {
    event?.preventDefault();
    await saveRules(content);
  }

  const dirty = content !== savedContent;
  const communityBusy = saving || Boolean(communityAction);
  const locked = status !== "connected" || communityBusy;
  let rulePreview = "";
  let builderError = "";
  try {
    rulePreview = buildAlertRule(builderForm, content);
  } catch (previewError) {
    builderError = previewError.message;
  }

  function updateBuilderField(event) {
    setBuilderForm((current) => ({
      ...current,
      [event.target.name]: event.target.value,
    }));
    setBuilderFeedback(null);
  }

  async function applyGeneratedRule(event) {
    event.preventDefault();
    if (!rulePreview || locked) return;
    const existing = content.trimEnd();
    const nextContent = `${existing}${existing ? "\n" : ""}${rulePreview}\n`;
    setError("");
    setDetails("");
    setMessage("");
    await saveRules(nextContent, true);
  }

  async function manageCommunityRules(action) {
    if (communityBusy) return;
    const confirmations = {
      install: community?.installed
        ? "Download and enable the latest official GPLv2 Snort Community Rules? Snort will validate the full configuration and restart."
        : "Install and enable the official GPLv2 Snort Community Rules? Snort will validate the full configuration and restart. This can add hundreds of detections.",
      update: `Download the latest official GPLv2 Snort Community Rules? Their current ${community?.enabled ? "enabled" : "disabled"} state will be preserved. Snort will validate the full configuration and restart.`,
      enable: "Enable the downloaded GPLv2 Community Rules? Snort will validate the full configuration and restart.",
      disable: "Disable Community Rules? The downloaded copy will be retained. Snort will validate and restart.",
      remove: "Remove the downloaded Community Rules and disable them? Snort will validate and restart.",
    };
    if (!window.confirm(confirmations[action])) return;

    setCommunityAction(action);
    setCommunityError("");
    setCommunityDetails("");
    setCommunityMessage("");
    try {
      const payload = await readResponse(
        await fetch(COMMUNITY_API_URL, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ action }),
        }),
      );
      setCommunity(payload);
      setCommunityMessage(payload.message);
    } catch (actionError) {
      setCommunityError(actionError.message);
      setCommunityDetails([actionError.details, actionError.rollback].filter(Boolean).join("\n"));
    } finally {
      setCommunityAction("");
    }
  }

  const ruleSummaries = parseRuleSummaries(content);
  const savedLines = new Set(savedContent.split(/\r?\n/).map((line) => line.trim()));

  return (
    <section className="rules-panel">
      <div className="rules-heading">
        <div>
          <p className="eyebrow">CUSTOM DETECTION RULES</p>
          <h2>Local alert rules <span>{ruleCount}</span></h2>
          <p className="rules-copy">
            Manage UI-owned alert rules. Packaged Snort rule files are not changed.
          </p>
        </div>
        <div className="rules-heading-actions">
          <div className="rules-info">
            <button
              className="rules-info-trigger"
              type="button"
              aria-label="Show rule validation details"
              aria-describedby="rules-validation-tooltip"
            >
              !
            </button>
            <span className="rules-info-tooltip" id="rules-validation-tooltip" role="tooltip">
              Snort checks the full configuration first. If it passes, the Snort service restarts to load your changes.
            </span>
          </div>
          <button
            className="secondary-button"
            type="button"
            onClick={() => {
              void loadRules();
              void loadCommunityRules();
            }}
            disabled={saving || Boolean(communityAction)}
          >
            Reload rules
          </button>
        </div>
      </div>

      {status === "error" && (
        <div className="notice notice-error" role="status">
          <strong>Rule manager unavailable</strong>
          <span>{error}</span>
          <span className="notice-help">
            Install the local rules manager using the README instructions. The editor stays read-only until it connects.
          </span>
        </div>
      )}
      {status === "conflict" && (
        <div className="notice notice-error" role="status">
          <strong>Rules changed elsewhere</strong>
          <span>{error}</span>
          <button className="inline-button" type="button" onClick={loadRules}>Reload latest</button>
        </div>
      )}
      {status === "connected" && error && (
        <div className="notice notice-error" role="alert">
          <strong>Could not apply rules</strong>
          <span>{error}</span>
          {details && <pre className="rule-output">{details}</pre>}
        </div>
      )}
      {message && (
        <div className="notice notice-success" role="status">
          <strong>Rules saved</strong>
          <span>{message}</span>
        </div>
      )}

      <section className="managed-rules" aria-labelledby="managed-rules-heading">
        <div className="managed-rules-toolbar">
          <details className="managed-rules-disclosure">
            <summary className="managed-rules-heading">
              <div>
                <p className="eyebrow">YOUR CUSTOM RULES</p>
                <h3 id="managed-rules-heading">Rule list <span>{ruleSummaries.length}</span></h3>
              </div>
              {dirty && <span className="draft-indicator">Unsaved draft changes</span>}
            </summary>
            {ruleSummaries.length === 0 ? (
              <p className="empty-rules">No custom alert rules yet. Create one below to see it listed here.</p>
            ) : (
              <ul className="managed-rule-list">
                {ruleSummaries.map((rule) => (
                  <li className="managed-rule" key={`${rule.lineIndex}-${rule.sid}`}>
                    <div className="managed-rule-details">
                      <div className="managed-rule-title">
                        <strong>{rule.message}</strong>
                        <span className={savedLines.has(rule.line) ? "rule-state saved" : "rule-state draft"}>
                          {savedLines.has(rule.line) ? "Saved" : "Draft"}
                        </span>
                      </div>
                      <div className="managed-rule-meta">
                        <span>{rule.protocol.toUpperCase()}</span>
                        {rule.source && <span>{rule.source} {rule.direction} {rule.destination}</span>}
                        <span>{rule.priority ? `${rule.severity} · Priority ${rule.priority}` : "No priority set"}</span>
                        {rule.sid && <span>SID {rule.sid}</span>}
                      </div>
                      <code className="managed-rule-signature">{rule.line}</code>
                    </div>
                    <button
                      className="inline-button remove-rule"
                      type="button"
                      disabled={locked}
                      onClick={() => {
                        setContent((current) => current
                          .split("\n")
                          .filter((_, index) => index !== rule.lineIndex)
                          .join("\n"));
                        setMessage("");
                        setError("");
                      }}
                      aria-label={`Remove ${rule.message} from the draft`}
                    >
                      Remove
                    </button>
                  </li>
                ))}
              </ul>
            )}
            <div className="managed-rules-save">
              <button
                className="apply-button"
                type="button"
                onClick={() => void applyRules()}
                disabled={locked || !dirty}
              >
                {saving ? "Validating and saving…" : "Save changes"}
              </button>
            </div>
          </details>
        </div>
      </section>

      <section className="rule-builder">
        <details className="builder-disclosure">
          <summary className="builder-heading">
            <div>
              <h3>Create an alert rule</h3>
              <p>Choose what traffic to watch. We’ll generate the Snort rule for you.</p>
            </div>
          </summary>
          <form onSubmit={applyGeneratedRule}>
            <div className="builder-grid">
              <label className="builder-field field-wide">
                <span>Alert description</span>
                <input
                  name="message"
                  value={builderForm.message}
                  onChange={updateBuilderField}
                  maxLength={100}
                  placeholder="e.g. Ping to my network"
                  spellCheck="false"
                  autoCapitalize="off"
                  autoCorrect="off"
                  required
                  disabled={locked}
                />
                <small>A short name shown in the alert feed</small>
              </label>
              <label className="builder-field">
                <span>Traffic type</span>
                <select name="protocol" value={builderForm.protocol} onChange={updateBuilderField} disabled={locked}>
                  <option value="icmp">Ping / ICMP</option>
                  <option value="tcp">TCP connection</option>
                  <option value="udp">UDP traffic</option>
                  <option value="ip">Any IP traffic</option>
                </select>
              </label>
              <label className="builder-field">
                <span>Severity</span>
                <select name="priority" value={builderForm.priority} onChange={updateBuilderField} disabled={locked}>
                  <option value="1">Critical · Priority 1</option>
                  <option value="2">High · Priority 2</option>
                  <option value="3">Medium · Priority 3</option>
                  <option value="4">Low · Priority 4</option>
                </select>
              </label>
              {builderForm.protocol === "icmp" && (
                <label className="builder-field">
                  <span>ICMP message</span>
                  <select name="icmpType" value={builderForm.icmpType} onChange={updateBuilderField} disabled={locked}>
                    <option value="8">Ping request</option>
                    <option value="0">Ping reply</option>
                    <option value="3">Destination unreachable</option>
                    <option value="11">Time exceeded</option>
                    <option value="any">Any ICMP message</option>
                  </select>
                </label>
              )}
              <label className="builder-field">
                <span>From network</span>
                <input
                  name="source"
                  value={builderForm.source}
                  onChange={updateBuilderField}
                  placeholder="any or $EXTERNAL_NET"
                  disabled={locked}
                />
              </label>
              <label className="builder-field">
                <span>Direction</span>
                <select name="direction" value={builderForm.direction} onChange={updateBuilderField} disabled={locked}>
                  <option value="->">To destination</option>
                  <option value="<>">Both directions</option>
                </select>
              </label>
              <label className="builder-field">
                <span>To network</span>
                <input
                  name="destination"
                  value={builderForm.destination}
                  onChange={updateBuilderField}
                  placeholder="any or $HOME_NET"
                  disabled={locked}
                />
              </label>
              {(builderForm.protocol === "tcp" || builderForm.protocol === "udp") && (
                <>
                  <label className="builder-field">
                    <span>From port</span>
                    <input
                      name="sourcePort"
                      value={builderForm.sourcePort}
                      onChange={updateBuilderField}
                      placeholder="any, 443, 1000:2000"
                      disabled={locked}
                    />
                  </label>
                  <label className="builder-field">
                    <span>To port</span>
                    <input
                      name="destinationPort"
                      value={builderForm.destinationPort}
                      onChange={updateBuilderField}
                      placeholder="any, 22, 80:443"
                      disabled={locked}
                    />
                  </label>
                </>
              )}
            </div>
            <div className="builder-preview">
              <span>Rule preview</span>
              <code>
                {rulePreview ||
                  (builderForm.message.trim()
                    ? builderError
                    : "Enter a description to preview the rule.")}
              </code>
            </div>
            <div className="builder-footer">
              <div>
                {builderForm.message.trim() && builderError && (
                  <span className="builder-error" role="alert">{builderError}</span>
                )}
                {builderFeedback && (
                  <span
                    className={`builder-feedback ${builderFeedback.type}`}
                    role={builderFeedback.type === "error" ? "alert" : "status"}
                  >
                    {builderFeedback.text}
                  </span>
                )}
              </div>
              <div className="builder-actions">
                <button
                  className="apply-button"
                  type="submit"
                  disabled={locked || !rulePreview}
                >
                  {saving ? "Saving…" : "Save"}
                </button>
              </div>
            </div>
          </form>

          <div className="rule-editor">
            <div className="editor-label">
              <label htmlFor="rule-content">Snort alert signatures</label>
              <span>{ruleCount} saved · {dirty ? "Unsaved edits" : "No pending edits"}</span>
            </div>
            <details className="advanced-editor">
              <summary>Open raw rule editor</summary>
              <textarea
                id="rule-content"
                value={content}
                onChange={(event) => {
                  setContent(event.target.value);
                  setMessage("");
                  setError("");
                }}
                disabled={status !== "connected" || saving}
                spellCheck="false"
                autoCapitalize="off"
                autoComplete="off"
                aria-describedby="rule-editor-help"
              />
              <p id="rule-editor-help" className="editor-help">
                One complete <code>alert</code> rule per line; blank lines and comments are allowed. Other Snort actions and configuration directives are rejected.
              </p>
            </details>
            <div className="editor-actions">
              <span className="rule-file">
                {file || "Managed rule file not connected"} · reloads {service}. Save changes from the rule list above.
              </span>
            </div>
          </div>
        </details>
      </section>

      <section className="community-rules">
        <details className="community-disclosure">
          <summary className="community-heading">
            <div>
              <p className="eyebrow">OFFICIAL SNORT RULES</p>
              <h3 id="community-rules-heading">GPLv2 Community Rules</h3>
              <p className="community-description">
                From the official Snort community package. Only GPLv2 community rules are managed here.
              </p>
            </div>
          </summary>
          <div className="community-status">
            {community ? (
              <>
                <span className={`community-state ${community.enabled ? "enabled" : ""}`}>
                  {community.enabled ? "Enabled" : community.installed ? "Downloaded · disabled" : "Not installed"}
                </span>
                {community.installed && (
                  <>
                    <span>
                      {community.enabled ? community.activeRuleCount : community.downloadedRuleCount}{" "}
                      {community.enabled ? "active rules" : "downloaded rules"}
                    </span>
                    {community.downloadedAt && (
                      <span>Updated {new Date(community.downloadedAt).toLocaleString()}</span>
                    )}
                    {community.checksum && <span>SHA-256 {community.checksum.replace(/^sha256-/, "").slice(0, 12)}…</span>}
                    <span>GPL license and AUTHORS credits retained</span>
                  </>
                )}
                <span>{community.license}</span>
              </>
            ) : (
              <span>{communityError ? "Community rules status unavailable" : "Loading community rules status…"}</span>
            )}
          </div>
          {communityError && (
            <div className="notice notice-error" role="alert">
              <strong>Community rules action failed</strong>
              <span>{communityError}</span>
              {communityDetails && <pre className="rule-output">{communityDetails}</pre>}
            </div>
          )}
          {communityMessage && (
            <div className="notice notice-success" role="status">
              <strong>Community rules updated</strong>
              <span>{communityMessage}</span>
            </div>
          )}
          <div className="community-actions">
            <span>
              Snort validates changes and restarts only after a successful check. Review the{" "}
              <a href="https://www.gnu.org/licenses/old-licenses/gpl-2.0.html" target="_blank" rel="noreferrer">GPLv2 license</a>
              {" "}or the <a href="https://www.snort.org/downloads/#rule-downloads" target="_blank" rel="noreferrer">official source</a>.
            </span>
            {!community?.installed ? (
              <button
                className="apply-button"
                type="button"
                disabled={!community || communityBusy}
                onClick={() => void manageCommunityRules("install")}
              >
                {communityAction === "install" ? "Downloading, validating & restarting…" : "Install & enable"}
              </button>
            ) : (
              <>
                <button
                  className="secondary-button"
                  type="button"
                  disabled={communityBusy}
                  onClick={() => void manageCommunityRules(community.enabled ? "update" : "enable")}
                >
                  {communityAction === "install" || communityAction === "update" || communityAction === "enable"
                    ? "Applying…"
                    : community.enabled ? "Update rules" : "Enable rules"}
                </button>
                {community.enabled ? (
                  <button
                    className="secondary-button"
                    type="button"
                    disabled={communityBusy}
                    onClick={() => void manageCommunityRules("disable")}
                  >
                    {communityAction === "disable" ? "Disabling…" : "Disable"}
                  </button>
                ) : (
                  <>
                    <button
                      className="secondary-button"
                      type="button"
                      disabled={communityBusy}
                      onClick={() => void manageCommunityRules("update")}
                    >
                      {communityAction === "update" ? "Updating…" : "Update rules"}
                    </button>
                    <button
                      className="inline-button"
                      type="button"
                      disabled={communityBusy}
                      onClick={() => void manageCommunityRules("remove")}
                    >
                      {communityAction === "remove" ? "Removing…" : "Remove"}
                    </button>
                  </>
                )}
              </>
            )}
          </div>
          <p className="community-source">Source: {community?.source ?? "Snort Community Rules"} · License: GPLv2</p>
        </details>
      </section>

    </section>
  );
}

export default RulesPanel;
