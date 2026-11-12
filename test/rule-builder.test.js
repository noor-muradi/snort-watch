import assert from "node:assert/strict";
import test from "node:test";
import { buildAlertRule, nextLocalSid } from "../src/rule-builder.js";
import { validateRuleContent } from "../server/rules-manager.mjs";

test("builds a prioritized ICMP echo rule with an automatic SID", () => {
  const rule = buildAlertRule({
    message: "Ping to home network",
    protocol: "icmp",
    source: "any",
    destination: "$HOME_NET",
    priority: "2",
    icmpType: "8",
  });
  assert.equal(
    rule,
    'alert icmp any any -> $HOME_NET any (msg:"Ping to home network"; itype:8; priority:2; sid:9000000; rev:1;)',
  );
  assert.deepEqual(validateRuleContent(rule), []);
});

test("builds TCP port ranges and bidirectional rules", () => {
  const rule = buildAlertRule({
    message: "Web ports",
    protocol: "tcp",
    source: "$EXTERNAL_NET",
    sourcePort: "any",
    destination: "192.0.2.0/24",
    destinationPort: "80:443",
    direction: "<>",
    priority: "3",
  });
  assert.match(
    rule,
    /^alert tcp \$EXTERNAL_NET any <> 192\.0\.2\.0\/24 80:443 \(msg:"Web ports"; priority:3; sid:9000000; rev:1;\)$/,
  );
});

test("escapes quotes and backslashes in alert descriptions", () => {
  const rule = buildAlertRule({
    message: 'User said "hello" \\ test',
    protocol: "udp",
    priority: "1",
  });
  assert.match(rule, /msg:"User said \\"hello\\" \\\\ test";/);
});

test("chooses an unused SID from the local range", () => {
  assert.equal(
    nextLocalSid("alert icmp any any -> any any (sid:9000000; rev:1;)"),
    9000001,
  );
});

test("rejects invalid networks, ports, priorities, and messages", () => {
  const base = { message: "test", protocol: "tcp", priority: "2" };
  assert.throws(() => buildAlertRule({ ...base, source: "any; include foo" }), /Source network/);
  assert.throws(() => buildAlertRule({ ...base, destinationPort: "80; drop" }), /Destination port/);
  assert.throws(() => buildAlertRule({ ...base, priority: "0" }), /priority/);
  assert.throws(() => buildAlertRule({ ...base, message: "   " }), /description/);
  assert.throws(() => buildAlertRule({ ...base, message: "x".repeat(101) }), /100 characters/);
});
