import assert from "node:assert/strict";
import test from "node:test";
import {
  validateCommunityArchiveMembers,
  validateCommunityRuleFile,
  validateRuleContent,
} from "../server/rules-manager.mjs";

const gplv2Header =
  "# Distributed under the GNU General Public License (GPL), v2.\n";

test("accepts comments, blank lines, and complete alert rules", () => {
  assert.deepEqual(
    validateRuleContent(
      "# Local custom alerts\n\nalert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:\"SSH connection attempt\"; sid:9000001; rev:1;)",
    ),
    [],
  );
});

test("rejects other rule actions and Snort configuration directives", () => {
  const errors = validateRuleContent(
    "drop tcp any any -> any any (msg:\"drop\"; sid:1; rev:1;)\ninclude rules/other.rules",
  );
  assert.equal(errors.length, 2);
  assert.match(errors[0], /only Snort alert rules are allowed/);
  assert.match(errors[1], /only Snort alert rules are allowed/);
});

test("rejects incomplete or multiline alert rules", () => {
  assert.match(
    validateRuleContent("alert tcp any any -> any any")[0],
    /complete single-line Snort alert rule/,
  );
});

test("rejects non-string, NUL-containing, and oversized content", () => {
  assert.match(validateRuleContent(null)[0], /must be a string/);
  assert.match(validateRuleContent("alert tcp\0")[0], /NUL/);
  assert.match(validateRuleContent("x".repeat(128 * 1024 + 1))[0], /128 KiB/);
});

test("rejects more than 500 lines", () => {
  assert.match(validateRuleContent("\n".repeat(501))[0], /500 rule lines/);
});

test("accepts active community alerts with the GPLv2 attribution", () => {
  const result = validateCommunityRuleFile(
    `${gplv2Header}# alert tcp any any -> any any (msg:"disabled"; sid:1;)\n` +
      'alert tcp any any -> $HOME_NET 22 (msg:"SSH attempt"; sid:1001; rev:1;)\n',
  );
  assert.deepEqual(result, { errors: [], ruleCount: 1 });
});

test("rejects community content without GPLv2 attribution or with directives", () => {
  assert.match(
    validateCommunityRuleFile('alert tcp any any -> any any (msg:"test"; sid:1;)').errors[0],
    /GPLv2 license/,
  );
  const result = validateCommunityRuleFile(
    `${gplv2Header}include other.rules\nalert tcp any any -> any any (msg:"test"; sid:1;)\n`,
  );
  assert.equal(result.ruleCount, 1);
  assert.match(result.errors[0], /only alert rules and comments/);
});

test("rejects an empty or oversized community ruleset", () => {
  assert.match(
    validateCommunityRuleFile(`${gplv2Header}# no active rules\n`).errors[0],
    /no active alert rules/,
  );
  assert.match(
    validateCommunityRuleFile(`${gplv2Header}${"x".repeat(5 * 1024 * 1024)}`).errors[0],
    /5 MiB limit/,
  );
});

test("accepts only safe archive member paths with the required GPL rules and license", () => {
  assert.deepEqual(
    validateCommunityArchiveMembers([
      "community-rules/",
      "community-rules/community.rules",
      "community-rules/LICENSE",
      "community-rules/AUTHORS",
    ]),
    [],
  );
  assert.match(
    validateCommunityArchiveMembers([
      "community-rules/community.rules",
      "community-rules/LICENSE",
      "community-rules/AUTHORS",
      "../outside",
    ])[0],
    /unsafe member path/,
  );
  assert.match(
    validateCommunityArchiveMembers([
      "community-rules/community.rules",
      "community-rules/LICENSE",
    ])[0],
    /missing expected/,
  );
});
