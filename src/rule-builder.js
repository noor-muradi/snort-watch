const LOCAL_SID_START = 9_000_000;
const LOCAL_SID_END = 9_999_999;

function validateNetwork(value, label) {
  const text = value.trim();
  if (text === "any" || /^\$[A-Z][A-Z0-9_]*$/.test(text)) {
    return text;
  }

  const ipv4 = text.match(/^((?:\d{1,3}\.){3}\d{1,3})(?:\/(\d{1,2}))?$/);
  if (ipv4) {
    const octets = ipv4[1].split(".").map(Number);
    if (octets.some((octet) => octet > 255) || Number(ipv4[2] ?? 32) > 32) {
      throw new Error(`${label} must be a valid IP address or CIDR range.`);
    }
    return text;
  }

  const ipv6 = text.match(/^([0-9a-fA-F:]+)(?:\/(\d{1,3}))?$/);
  if (ipv6 && ipv6[1].includes(":") && Number(ipv6[2] ?? 128) <= 128) {
    return text;
  }

  throw new Error(`${label} must be "any", a Snort network variable, or an IP/CIDR range.`);
}

function validatePort(value, label) {
  const text = value.trim();
  if (text === "any" || /^\$[A-Z][A-Z0-9_]*$/.test(text)) {
    return text;
  }

  if (!/^(?:\d{1,5})?(?::\d{0,5})?$/.test(text) || !/\d/.test(text)) {
    throw new Error(`${label} must be "any", a port number, a port range, or a Snort port variable.`);
  }

  const [start, end] = text.split(":").map((part) => (part ? Number(part) : null));
  if (
    (start !== null && (start < 1 || start > 65535)) ||
    (end !== undefined && end !== null && (end < 1 || end > 65535)) ||
    (start !== null && end !== undefined && end !== null && start > end)
  ) {
    throw new Error(`${label} must use ports from 1 to 65535 in ascending order.`);
  }
  return text;
}

export function nextLocalSid(content) {
  const used = new Set(
    [...content.matchAll(/\bsid\s*:\s*(\d+)\s*;/gi)].map((match) => Number(match[1])),
  );
  for (let sid = LOCAL_SID_START; sid <= LOCAL_SID_END; sid += 1) {
    if (!used.has(sid)) {
      return sid;
    }
  }
  throw new Error("No available automatic SID remains in the Snort Watch range.");
}

export function buildAlertRule(form, existingContent = "") {
  const message = form.message.trim();
  if (!message) {
    throw new Error("Enter a short description for the alert.");
  }
  if (message.length > 100) {
    throw new Error("Alert description must be 100 characters or fewer.");
  }
  if (/[\u0000-\u001f\u007f]/.test(message)) {
    throw new Error("Alert description cannot contain control characters.");
  }

  const protocol = String(form.protocol);
  if (!["icmp", "tcp", "udp", "ip"].includes(protocol)) {
    throw new Error("Choose ICMP, TCP, UDP, or IP as the protocol.");
  }

  const source = validateNetwork(form.source ?? "any", "Source network");
  const destination = validateNetwork(
    form.destination ?? "any",
    "Destination network",
  );
  const usesPorts = protocol === "tcp" || protocol === "udp";
  const sourcePort = usesPorts
    ? validatePort(form.sourcePort ?? "any", "Source port")
    : "any";
  const destinationPort = usesPorts
    ? validatePort(form.destinationPort ?? "any", "Destination port")
    : "any";
  const direction = form.direction ?? "->";
  if (!["->", "<>"].includes(direction)) {
    throw new Error("Choose one-way or bidirectional traffic.");
  }

  const priority = Number(form.priority);
  if (!Number.isInteger(priority) || priority < 1 || priority > 4) {
    throw new Error("Choose a priority from 1 to 4.");
  }

  let icmpType = "";
  if (protocol === "icmp" && form.icmpType && form.icmpType !== "any") {
    const type = Number(form.icmpType);
    if (!Number.isInteger(type) || type < 0 || type > 255) {
      throw new Error("Choose a valid ICMP message type.");
    }
    icmpType = ` itype:${type};`;
  }

  const sid = nextLocalSid(existingContent);
  const escapedMessage = message.replaceAll("\\", "\\\\").replaceAll('"', '\\"');
  return `alert ${protocol} ${source} ${sourcePort} ${direction} ${destination} ${destinationPort} (msg:"${escapedMessage}";${icmpType} priority:${priority}; sid:${sid}; rev:1;)`;
}
