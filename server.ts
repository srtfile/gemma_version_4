import { serve } from "https://deno.land/std@0.208.0/http/server.ts";

const PROXY_USER = Deno.env.get("PROXY_USER") ?? "";
const PROXY_PASS = Deno.env.get("PROXY_PASS") ?? "";

const PROXIES = [
  ["31.59.20.176",    6754],
  ["31.56.127.193",   7684],
  ["45.38.107.97",    6014],
  ["38.154.203.95",   5863],
  ["198.105.121.200", 6462],
  ["64.137.96.74",    6641],
  ["198.23.243.226",  6361],
  ["38.154.185.97",   6370],
  ["142.111.67.146",  5611],
  ["191.96.254.138",  6185],
];

function shuffle(arr: unknown[][]) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

async function fetchViaProxy(
  targetUrl: string,
  method = "GET",
  headers: Record<string, string> = {},
  body: string | null = null
): Promise<{ status: number; text: string }> {
  const proxies = shuffle(PROXIES);
  let lastErr = "no proxies";

  for (const [host, port] of proxies) {
    try {
      const proxyAuth = btoa(`${PROXY_USER}:${PROXY_PASS}`);
      const conn = await Deno.connect({ hostname: host as string, port: port as number });

      const target = new URL(targetUrl);
      const connectReq =
        `CONNECT ${target.hostname}:443 HTTP/1.1\r\n` +
        `Host: ${target.hostname}:443\r\n` +
        `Proxy-Authorization: Basic ${proxyAuth}\r\n\r\n`;

      await conn.write(new TextEncoder().encode(connectReq));

      // Read CONNECT response
      const buf = new Uint8Array(4096);
      await conn.read(buf);
      const connectResp = new TextDecoder().decode(buf);
      if (!connectResp.includes("200")) {
        conn.close();
        lastErr = `CONNECT failed: ${connectResp.split("\r\n")[0]}`;
        continue;
      }

      // TLS upgrade
      const tlsConn = await Deno.startTls(conn, { hostname: target.hostname });

      const reqHeaders: Record<string, string> = {
        "Host": target.hostname,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "*/*",
        "Connection": "close",
        ...headers,
      };

      const bodyBytes = body ? new TextEncoder().encode(body) : null;
      if (bodyBytes) reqHeaders["Content-Length"] = String(bodyBytes.length);

      const hdrStr = Object.entries(reqHeaders)
        .map(([k, v]) => `${k}: ${v}`).join("\r\n");

      const reqLine = `${method} ${target.pathname}${target.search} HTTP/1.1\r\n${hdrStr}\r\n\r\n`;
      await tlsConn.write(new TextEncoder().encode(reqLine));
      if (bodyBytes) await tlsConn.write(bodyBytes);

      // Read full response
      const chunks: Uint8Array[] = [];
      const tmp = new Uint8Array(16384);
      while (true) {
        const n = await tlsConn.read(tmp);
        if (n === null) break;
        chunks.push(tmp.slice(0, n));
      }
      tlsConn.close();

      const full = new Uint8Array(chunks.reduce((a, c) => a + c.length, 0));
      let off = 0;
      for (const c of chunks) { full.set(c, off); off += c.length; }

      const fullStr = new TextDecoder().decode(full);
      const sep = fullStr.indexOf("\r\n\r\n");
      if (sep === -1) { lastErr = "no header sep"; continue; }

      const statusLine = fullStr.split("\r\n")[0];
      const status = parseInt(statusLine.split(" ")[1]);
      const responseBody = fullStr.slice(sep + 4);

      return { status, text: responseBody };
    } catch (e) {
      lastErr = e instanceof Error ? e.message : String(e);
      continue;
    }
  }

  throw new Error(`All proxies failed: ${lastErr}`);
}

serve(async (req: Request) => {
  const url = new URL(req.url);

  // CORS preflight
  if (req.method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "*",
      },
    });
  }

  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "text/plain; charset=utf-8",
  };

  // Health check
  if (url.pathname === "/") {
    return new Response("proxy ok", { headers: corsHeaders });
  }

  // /fetch endpoint
  if (url.pathname === "/fetch") {
    const target  = url.searchParams.get("url");
    const method  = url.searchParams.get("method") ?? "GET";
    const token   = url.searchParams.get("token") ?? "";
    const referer = url.searchParams.get("referer") ?? "";

    if (!target) {
      return new Response("missing url param", { status: 400, headers: corsHeaders });
    }

    const headers: Record<string, string> = {};
    if (token)   headers["X-CSRF-Token"] = token;
    if (referer) {
      headers["Referer"] = referer;
      headers["Origin"]  = new URL(referer).origin;
      headers["Content-Type"] = "application/x-www-form-urlencoded";
    }

    try {
      const result = await fetchViaProxy(target, method, headers, method === "POST" ? "" : null);
      return new Response(result.text, {
        status: result.status,
        headers: corsHeaders,
      });
    } catch (e) {
      return new Response(
        JSON.stringify({ error: e instanceof Error ? e.message : String(e) }),
        { status: 502, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }
  }

  return new Response("not found", { status: 404, headers: corsHeaders });
});
