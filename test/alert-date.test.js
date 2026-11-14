import assert from "node:assert/strict";
import test from "node:test";
import {
  alertDate,
  isWithinAlertDateRange,
  localDateStart,
} from "../src/alert-date.js";

test("prefers the ingestion timestamp for alert date filtering", () => {
  const date = alertDate({
    received_at: "2026-11-14T10:15:00.000Z",
    timestamp: "11/13-10:15:00",
  });

  assert.equal(date.toISOString(), "2026-11-14T10:15:00.000Z");
});

test("assigns the nearest year to Snort timestamps without a year", () => {
  const now = new Date(2026, 0, 2, 12);
  const date = alertDate({ timestamp: "12/31-23:59:59" }, now);

  assert.equal(date.getFullYear(), 2025);
  assert.equal(date.getMonth(), 11);
  assert.equal(date.getDate(), 31);
});

test("parses valid local date boundaries and rejects invalid calendar dates", () => {
  const date = localDateStart("2026-11-14");

  assert.equal(
    date.getTime(),
    new Date(2026, 10, 14).getTime(),
  );
  assert.equal(localDateStart("2026-02-30"), null);
  assert.equal(localDateStart("invalid"), null);
  assert.equal(alertDate({ timestamp: "02/30-12:00:00" }), null);
});

test("includes both selected date boundaries and omits undated alerts", () => {
  const start = localDateStart("2026-11-13");
  const end = localDateStart("2026-11-14");
  const now = new Date(2026, 10, 14, 12);

  assert.equal(
    isWithinAlertDateRange(
      { received_at: new Date(2026, 10, 13, 0).toISOString() },
      start,
      end,
      now,
    ),
    true,
  );
  assert.equal(
    isWithinAlertDateRange(
      { received_at: new Date(2026, 10, 14, 23, 59, 59).toISOString() },
      start,
      end,
      now,
    ),
    true,
  );
  assert.equal(
    isWithinAlertDateRange({ message: "no timestamp" }, start, end, now),
    false,
  );
  assert.equal(isWithinAlertDateRange({ message: "any date" }, null, null), true);
});
