import { useEffect, useMemo, useState } from "react";
import RulesPanel from "./RulesPanel.jsx";

const REFRESH_MS = 5000;

function field(alert, ...names) {
  for (const name of names) {
    if (alert[name] !== undefined && alert[name] !== null && alert[name] !== "") {
      return alert[name];
    }
  }
  return null;
}

function severityFor(alert) {
  const priority = Number(field(alert, "priority", "priority_id"));
  if (priority === 1) return "critical";
  if (priority === 2) return "high";
  if (priority === 3) return "medium";
  if (priority >= 4) return "low";
  return "unknown";
}

function formatTime(value) {
  if (!value) return "—";
  const text = String(value);
  const snortTime = text.match(
    /^(\d{2})\/(\d{2})-(\d{2}:\d{2}:\d{2}(?:\.\d+)?)$/,
  );
  const candidate = snortTime
    ? `${new Date().getFullYear()}-${snortTime[1]}-${snortTime[2]}T${snortTime[3]}`
    : text;
  const date = new Date(candidate);
  return Number.isNaN(date.getTime())
    ? text
    : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" });
}

function endpoint(alert, side) {
  const source = side === "source";
  const address = field(
    alert,
    source ? "source_ip" : "destination_ip",
    source ? "src" : "dst",
    source ? "src_addr" : "dst_addr",
  );
  const port = field(
    alert,
    source ? "source_port" : "destination_port",
    source ? "srcport" : "dstport",
    source ? "src_port" : "dst_port",
  );
  if (!address) return "—";
  return port ? `${address}:${port}` : String(address);
}

function messageOf(alert) {
  return String(field(alert, "message", "msg", "signature") ?? "Unlabeled alert");
}

function severityLabel(severity) {
  return severity === "unknown"
    ? "No priority"
    : `${severity[0].toUpperCase()}${severity.slice(1)}`;
}

function App() {
  const [alerts, setAlerts] = useState([]);
  const [status, setStatus] = useState("loading");
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [lastUpdated, setLastUpdated] = useState(null);
  const [source, setSource] = useState("");
  const [activeView, setActiveView] = useState(() =>
    window.sessionStorage.getItem("snort-watch-active-view") === "rules" ? "rules" : "alerts",
  );
  const [pageSize, setPageSize] = useState(10);
  const [currentPage, setCurrentPage] = useState(1);

  useEffect(() => {
    let active = true;

    async function refresh() {
      try {
        const response = await fetch("/api/alerts?limit=1000");
        const payload = await response.json();
        if (!response.ok) {
          throw new Error(payload.error ?? `Request failed (${response.status})`);
        }
        if (!active) return;
        setAlerts(Array.isArray(payload.alerts) ? payload.alerts : []);
        setLastUpdated(new Date(payload.updatedAt));
        setSource(payload.source ?? "");
        setError(
          payload.malformedLines
            ? `${payload.malformedLines} malformed JSON line(s) were skipped.`
            : "",
        );
        setStatus("connected");
      } catch (fetchError) {
        if (!active) return;
        setError(fetchError.message);
        setStatus("error");
      }
    }

    void refresh();
    const timer = window.setInterval(refresh, REFRESH_MS);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    window.sessionStorage.setItem("snort-watch-active-view", activeView);
  }, [activeView]);

  const filteredAlerts = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return alerts.filter((alert) => {
      const severity = severityFor(alert);
      if (severityFilter !== "all" && severity !== severityFilter) return false;
      if (!needle) return true;
      const haystack = [
        messageOf(alert),
        field(alert, "signature_id", "sid", "sig_id"),
        field(alert, "generator_id", "gid", "sig_generator"),
        field(alert, "protocol", "proto"),
        endpoint(alert, "source"),
        endpoint(alert, "destination"),
        field(alert, "classification"),
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(needle);
    });
  }, [alerts, query, severityFilter]);

  const summary = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const alert of alerts) {
      const severity = severityFor(alert);
      if (severity in counts) counts[severity] += 1;
    }
    return counts;
  }, [alerts]);

  const pageCount = Math.max(1, Math.ceil(filteredAlerts.length / pageSize));
  const displayedPage = Math.min(currentPage, pageCount);
  const pageStart = (displayedPage - 1) * pageSize;
  const pageAlerts = filteredAlerts.slice(pageStart, pageStart + pageSize);
  const paginationStart = Math.max(1, Math.min(displayedPage - 2, pageCount - 4));
  const paginationEnd = Math.min(pageCount, paginationStart + 4);

  return (
    <main className="shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="Snort Watch home">
          <span className="brand-mark">S</span>
          <span>SNORT<span className="brand-light">WATCH</span></span>
        </a>
        <nav className="top-nav" aria-label="Dashboard sections">
          <button
            className={activeView === "alerts" ? "active" : ""}
            type="button"
            onClick={() => setActiveView("alerts")}
          >
            Alerts
          </button>
          <button
            className={activeView === "rules" ? "active" : ""}
            type="button"
            onClick={() => setActiveView("rules")}
          >
            Rules
          </button>
        </nav>
        <div className="connection">
          <span className={`connection-dot ${status}`} />
          <span>{status === "connected" ? "Live feed" : status === "loading" ? "Connecting" : "Feed unavailable"}</span>
        </div>
      </header>

      <section className="intro">
        <div>
          <p className="eyebrow">NETWORK SECURITY · SENSOR OVERVIEW</p>
          <h1>{activeView === "alerts" ? "Alert dashboard" : "Rule management"}</h1>
          <p className="intro-copy">
            {activeView === "alerts"
              ? "A live view of detections reported by your Snort sensor."
              : "Manage custom alert rules and apply validated changes to Snort."}
          </p>
        </div>
        {activeView === "alerts" && (
          <div className="refresh-stamp">
            <span className="live-pulse" />
            Refreshes every 5 seconds
            <small>{lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString()}` : "Waiting for first update"}</small>
          </div>
        )}
      </section>

      {activeView === "alerts" && error && (
        <div className={`notice ${status === "error" ? "notice-error" : ""}`} role="status">
          <strong>{status === "error" ? "Feed problem" : "Log notice"}</strong>
          <span>{error}</span>
          {status === "error" && (
            <span className="notice-help">
              Start the JSON bridge and API as described in the README.
            </span>
          )}
        </div>
      )}

      {activeView === "rules" ? <RulesPanel /> : (
      <>
      <section className="summary-grid" aria-label="Alert summary">
        <article className="summary-card total-card">
          <span className="summary-label">Loaded alerts</span>
          <strong>{alerts.length.toLocaleString()}</strong>
          <span className="summary-foot">Most recent events</span>
          <span className="total-glyph" aria-hidden="true">⌁</span>
        </article>
        {["critical", "high", "medium", "low"].map((severity) => (
          <button
            className={`summary-card severity-card ${severity} ${severityFilter === severity ? "selected" : ""}`}
            key={severity}
            onClick={() => {
              setSeverityFilter(severityFilter === severity ? "all" : severity);
              setCurrentPage(1);
            }}
            aria-pressed={severityFilter === severity}
          >
            <span className="summary-label">{severityLabel(severity)}</span>
            <strong>{summary[severity].toLocaleString()}</strong>
            <span className="summary-foot">Priority {severity === "critical" ? "1" : severity === "high" ? "2" : severity === "medium" ? "3" : "4+"}</span>
            <span className="severity-icon" aria-hidden="true">{severity === "critical" ? "!" : severity === "high" ? "↑" : severity === "medium" ? "◆" : "·"}</span>
          </button>
        ))}
      </section>

      <section className="feed-panel">
        <div className="feed-heading">
          <div>
            <p className="eyebrow">DETECTION STREAM</p>
            <h2>Recent alerts <span>{filteredAlerts.length}</span></h2>
          </div>
          <label className="search">
            <span aria-hidden="true">⌕</span>
            <input
              type="search"
              placeholder="Search signature, IP, protocol..."
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setCurrentPage(1);
              }}
              aria-label="Search alerts"
            />
            <kbd>/</kbd>
          </label>
        </div>
        <div className="filter-row">
          <div className="filter-tabs" role="group" aria-label="Filter by severity">
            {["all", "critical", "high", "medium", "low"].map((severity) => (
              <button
                key={severity}
                className={severityFilter === severity ? "active" : ""}
                onClick={() => {
                  setSeverityFilter(severity);
                  setCurrentPage(1);
                }}
              >
                {severity === "all" ? "All alerts" : severityLabel(severity)}
              </button>
            ))}
          </div>
          <span className="loaded-note">Latest {alerts.length} events</span>
        </div>

        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>SEVERITY</th>
                <th>ALERT</th>
                <th>SOURCE</th>
                <th>DESTINATION</th>
                <th>PROTO</th>
                <th>TIME</th>
              </tr>
            </thead>
            <tbody>
              {pageAlerts.map((alert, index) => {
                const alertIndex = pageStart + index;
                const severity = severityFor(alert);
                const signatureId = field(alert, "signature_id", "sid", "sig_id");
                const generatorId = field(alert, "generator_id", "gid", "sig_generator");
                return (
                  <tr key={`${alert.event_id ?? `${signatureId}-${alertIndex}`}-${alert.timestamp ?? ""}-${alertIndex}`}>
                    <td>
                      <span className={`badge ${severity}`}>
                        <i />
                        {severityLabel(severity)}
                      </span>
                    </td>
                    <td className="alert-cell">
                      <strong>{messageOf(alert)}</strong>
                      <small>
                        {generatorId != null ? `${generatorId}:` : ""}
                        {signatureId ?? "Signature unavailable"}
                        {field(alert, "signature_rev", "rev", "sig_rev") != null
                          ? `:${field(alert, "signature_rev", "rev", "sig_rev")}`
                          : ""}
                        {field(alert, "classification")
                          ? ` · ${field(alert, "classification")}`
                          : ""}
                      </small>
                    </td>
                    <td className="mono">{endpoint(alert, "source")}</td>
                    <td className="mono">{endpoint(alert, "destination")}</td>
                    <td><span className="protocol">{String(field(alert, "protocol", "proto") ?? "—").toUpperCase()}</span></td>
                    <td className="time-cell">{formatTime(field(alert, "timestamp", "ts"))}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {filteredAlerts.length === 0 && (
            <div className="empty-state">
              <span className="empty-icon">⌁</span>
              <strong>{status === "error" ? "Waiting for the alert feed" : alerts.length ? "No matching alerts" : "No alerts yet"}</strong>
              <p>
                {alerts.length
                  ? "Try a different search or severity filter."
                  : "New Snort detections will appear here as they are written to the JSON log."}
              </p>
            </div>
          )}
        </div>
        {filteredAlerts.length > 0 && (
          <div className="pagination">
            <label className="page-size">
              <span>Rows per page</span>
              <select
                aria-label="Rows per page"
                value={pageSize}
                onChange={(event) => {
                  setPageSize(Number(event.target.value));
                  setCurrentPage(1);
                }}
              >
                {[10, 25, 50, 100].map((size) => (
                  <option key={size} value={size}>{size}</option>
                ))}
              </select>
            </label>
            <span className="page-range">
              Showing {pageStart + 1}–{Math.min(pageStart + pageSize, filteredAlerts.length)} of {filteredAlerts.length}
            </span>
            <nav className="page-tabs" aria-label="Alert pages">
              <button
                type="button"
                aria-label="Previous page"
                disabled={displayedPage === 1}
                onClick={() => setCurrentPage(displayedPage - 1)}
              >
                ‹
              </button>
              {Array.from({ length: paginationEnd - paginationStart + 1 }, (_, index) => {
                const page = paginationStart + index;
                return (
                  <button
                    type="button"
                    key={page}
                    className={displayedPage === page ? "active" : ""}
                    aria-label={`Page ${page}`}
                    aria-current={displayedPage === page ? "page" : undefined}
                    onClick={() => setCurrentPage(page)}
                  >
                    {page}
                  </button>
                );
              })}
              <button
                type="button"
                aria-label="Next page"
                disabled={displayedPage === pageCount}
                onClick={() => setCurrentPage(displayedPage + 1)}
              >
                ›
              </button>
            </nav>
          </div>
        )}
        <footer className="feed-footer">
          <span><i className={`connection-dot ${status}`} /> {status === "connected" ? "Connected to local alert feed" : status === "loading" ? "Connecting to local alert feed" : "Disconnected from local alert feed"}</span>
          <span>{source ? `Source: ${source}` : "Source not configured"}</span>
        </footer>
      </section>
      </>
      )}
      <footer className="page-footer">
        <span>SNORT WATCH <b>·</b> {activeView === "rules" ? "RULE MANAGEMENT" : "LOCAL SENSOR DASHBOARD"}</span>
        <span>Alert data stays on this machine</span>
      </footer>
    </main>
  );
}

export default App;
