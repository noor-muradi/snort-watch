import assert from "node:assert/strict";
import test from "node:test";
import { parseSnortFastAlert } from "../server/snort-fast.js";

test("parses a Snort fast alert into normalized JSON fields", () => {
  const alert = parseSnortFastAlert(
    "11/11-14:12:34.123456 [**] [1:1000001:3] Suspicious request [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 192.0.2.15:51512 -> 198.51.100.8:443",
  );

  assert.deepEqual(alert, {
    timestamp: "11/11-14:12:34.123456",
    generator_id: 1,
    signature_id: 1000001,
    signature_rev: 3,
    event_id: "1:1000001:3",
    message: "Suspicious request",
    classification: "Attempted Information Leak",
    priority: 2,
    protocol: "TCP",
    source_ip: "192.0.2.15",
    source_port: 51512,
    destination_ip: "198.51.100.8",
    destination_port: 443,
  });
});

test("parses bracketed IPv6 endpoints and missing optional metadata", () => {
  const alert = parseSnortFastAlert(
    "11/11-14:12:34 [**] [1:7:1] IPv6 signature [**] {UDP} [2001:db8::1]:53 -> [2001:db8::2]:5353",
  );

  assert.equal(alert.source_ip, "2001:db8::1");
  assert.equal(alert.source_port, 53);
  assert.equal(alert.destination_ip, "2001:db8::2");
  assert.equal(alert.priority, null);
  assert.equal(alert.classification, null);
});

test("ignores lines that are not fast-format alerts", () => {
  assert.equal(parseSnortFastAlert("Snort initialization complete"), null);
});
