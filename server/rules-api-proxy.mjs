import { request as httpRequest } from "node:http";

const allowedPaths = new Set(["/api/rules", "/api/community-rules"]);

export function proxyRulesApi(request, response, url, socketPath) {
  const apiPath = url.pathname.slice("/rules-api".length);
  if (!allowedPaths.has(apiPath)) {
    response.writeHead(404, { "content-type": "application/json; charset=utf-8" });
    response.end(JSON.stringify({ error: "Rule API route not found." }));
    return;
  }
  if (!socketPath) {
    response.writeHead(503, { "content-type": "application/json; charset=utf-8" });
    response.end(JSON.stringify({ error: "Rule manager is not configured." }));
    return;
  }

  const headers = {};
  for (const name of ["content-type", "content-length", "origin"]) {
    if (request.headers[name]) headers[name] = request.headers[name];
  }

  const upstream = httpRequest(
    {
      socketPath,
      path: `${apiPath}${url.search}`,
      method: request.method,
      headers,
    },
    (upstreamResponse) => {
      const responseHeaders = {};
      for (const name of [
        "content-type",
        "cache-control",
        "access-control-allow-origin",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-max-age",
        "vary",
      ]) {
        if (upstreamResponse.headers[name]) {
          responseHeaders[name] = upstreamResponse.headers[name];
        }
      }
      response.writeHead(upstreamResponse.statusCode ?? 502, responseHeaders);
      upstreamResponse.pipe(response);
    },
  );
  upstream.on("error", (error) => {
    if (!response.headersSent) {
      response.writeHead(503, { "content-type": "application/json; charset=utf-8" });
      response.end(JSON.stringify({ error: `Rule manager unavailable: ${error.message}` }));
    } else {
      response.destroy(error);
    }
  });
  request.pipe(upstream);
}
