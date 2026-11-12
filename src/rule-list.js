const severityNames = {
  1: "Critical",
  2: "High",
  3: "Medium",
  4: "Low",
};

function optionValue(options, name) {
  const match = options.match(new RegExp(`\\b${name}\\s*:\\s*"((?:\\\\.|[^"\\\\])*)"`));
  return match?.[1]?.replace(/\\"/g, '"').replace(/\\\\/g, "\\") ?? "";
}

export function parseRuleSummaries(content) {
  return content
    .split(/\r?\n/)
    .flatMap((rawLine, lineIndex) => {
      const line = rawLine.trim();
      if (!line.startsWith("alert ")) return [];

      const openingParen = line.indexOf("(");
      const header = (openingParen < 0 ? line : line.slice(0, openingParen)).split(/\s+/);
      const options = openingParen < 0 ? "" : line.slice(openingParen + 1);
      const sid = options.match(/\bsid\s*:\s*(\d+)/)?.[1] ?? "";
      const priority = options.match(/\bpriority\s*:\s*([1-4])/)?.[1] ?? "";
      const message = optionValue(options, "msg");
      const isComplete = openingParen >= 0 &&
        line.endsWith(")") &&
        header.length >= 7 &&
        (header[4] === "->" || header[4] === "<>");

      return [{
        lineIndex,
        line,
        message: message || "Unparsed alert rule",
        protocol: isComplete ? header[1] : "custom",
        source: isComplete ? `${header[2]}:${header[3]}` : "",
        direction: isComplete ? header[4] : "",
        destination: isComplete ? `${header[5]}:${header[6]}` : "",
        sid,
        priority,
        severity: severityNames[priority] ?? "",
      }];
    });
}
