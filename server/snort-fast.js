const ALERT_PATTERN =
  /^\s*(?<timestamp>\d{2}\/\d{2}-\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+\[\*\*\]\s+\[(?<generator>\d+):(?<signatureId>\d+):(?<revision>\d+)\]\s+(?<message>.*?)\s+\[\*\*\](?:\s+\[Classification:\s*(?<classification>.*?)\])?(?:\s+\[Priority:\s*(?<priority>\d+)\])?\s+\{(?<protocol>[^}]+)\}\s+(?<source>.+?)\s+->\s+(?<destination>.+?)\s*$/;

function splitEndpoint(endpoint) {
  const ipv6 = endpoint.match(/^\[(.+)\]:(\d+)$/);
  if (ipv6) {
    return { ip: ipv6[1], port: Number(ipv6[2]) };
  }

  const ipv4 = endpoint.match(/^(.+):(\d+)$/);
  if (ipv4) {
    return { ip: ipv4[1], port: Number(ipv4[2]) };
  }

  return { ip: endpoint, port: null };
}

export function parseSnortFastAlert(line) {
  const match = ALERT_PATTERN.exec(line);
  if (!match?.groups) {
    return null;
  }

  const source = splitEndpoint(match.groups.source);
  const destination = splitEndpoint(match.groups.destination);
  const signatureId = Number(match.groups.signatureId);
  const priority = match.groups.priority
    ? Number(match.groups.priority)
    : null;

  return {
    timestamp: match.groups.timestamp,
    generator_id: Number(match.groups.generator),
    signature_id: signatureId,
    signature_rev: Number(match.groups.revision),
    event_id: `${match.groups.generator}:${signatureId}:${match.groups.revision}`,
    message: match.groups.message,
    classification: match.groups.classification ?? null,
    priority,
    protocol: match.groups.protocol,
    source_ip: source.ip,
    source_port: source.port,
    destination_ip: destination.ip,
    destination_port: destination.port,
  };
}
