import assert from "node:assert/strict";
import test from "node:test";
import { parseRuleSummaries } from "../src/rule-list.js";

test("summarizes generated rules with their message, traffic, priority, and SID", () => {
  const [rule] = parseRuleSummaries(
    '# saved\nalert icmp any any -> $HOME_NET any (msg:"Ping to \\"home\\""; itype:8; priority:2; sid:9000001; rev:1;)',
  );
  assert.equal(rule.message, 'Ping to "home"');
  assert.equal(rule.protocol, "icmp");
  assert.equal(rule.source, "any:any");
  assert.equal(rule.destination, "$HOME_NET:any");
  assert.equal(rule.severity, "High");
  assert.equal(rule.sid, "9000001");
  assert.equal(rule.lineIndex, 1);
});

test("keeps an unparsed alert visible rather than silently dropping it", () => {
  const [rule] = parseRuleSummaries("alert tcp any any -> any any");
  assert.equal(rule.message, "Unparsed alert rule");
  assert.equal(rule.protocol, "custom");
  assert.equal(rule.line, "alert tcp any any -> any any");
});
