import { randomUUID } from "crypto";
import { readFile } from "fs/promises";
import { join } from "path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { validateApiKey, recordUsage, createApiKey, getKeyByEmail, upgradeKey, getKeyUsage, TIER_LIMITS, TIER_PRICES } from "./lib/auth";
import type { Tier } from "./lib/auth";
import { log } from "./lib/logger";
import { handleOAuthRoute, unauthorizedResponse, type OAuthConfig } from "./lib/oauth";

import { analyzeProfile } from "./tools/profile-analysis";
import { scoreEngagement } from "./tools/engagement-scoring";
import { detectTrends } from "./tools/trend-detection";
import { researchHashtags } from "./tools/hashtag-research";
// Pro/Business tier tools
import { generateContentCalendar } from "./tools/content-calendar";
import { benchmarkCompetitors } from "./tools/competitor-benchmarks";

const PORT = parseInt(process.env.MCP_PORT || "4202");
const BASE_DIR = import.meta.dir || process.cwd();

// --- Page cache ---
const pageCache: Record<string, string> = {};
const MIME_TYPES: Record<string, string> = {
  ".html": "text/html",
  ".css": "text/css",
  ".js": "application/javascript",
  ".json": "application/json",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

async function loadPage(name: string): Promise<string> {
  if (pageCache[name]) return pageCache[name];
  let content = await readFile(join(BASE_DIR, "pages", name), "utf-8");
  content = content.replace(/style\.css\?v=\d+/g, 'style.css?v=3');
  if (content.includes('</body>')) {
    content = content.replace('</body>', '<script src="/static/nav.js"></script>\n</body>');
  }
  pageCache[name] = content;
  return content;
}

async function serveStatic(pathname: string): Promise<Response | null> {
  if (!pathname.startsWith("/static/") && !pathname.startsWith("/.well-known/")) return null;
  const filePath = pathname.startsWith("/.well-known/")
    ? join(BASE_DIR, "static", pathname)
    : join(BASE_DIR, pathname);
  try {
    const content = await readFile(filePath);
    const ext = pathname.substring(pathname.lastIndexOf("."));
    return new Response(content, {
      headers: {
        "Content-Type": MIME_TYPES[ext] || "application/octet-stream",
        "Cache-Control": "public, max-age=3600",
      },
    });
  } catch {
    return null;
  }
}

// --- MCP Server factory ---
function createMcpServer(tier: string = "free"): McpServer {
  const server = new McpServer({
    name: "ezbiz-social-media",
    version: "1.0.0",
  });

  server.tool(
    "analyze_profile",
    "Analyze a social media profile or brand presence — posting patterns, content themes, audience indicators, and growth recommendations.",
    {
      username: z.string().describe("Social media username or handle (e.g., '@hubspot')"),
      platform: z.enum(["twitter", "instagram", "linkedin", "facebook", "tiktok"]).optional().describe("Social media platform to analyze"),
      business_name: z.string().optional().describe("Business name for broader cross-platform search")
    },
    async (params) => {
      const result = await analyzeProfile({ ...params, tier });
      return { content: [{ type: "text", text: result }] };
    }
  );

  server.tool(
    "score_engagement",
    "Score social media engagement for a brand or topic — engagement rate estimates, content type effectiveness, posting time analysis, and benchmarks.",
    {
      brand_or_topic: z.string().describe("Brand name or topic to analyze (e.g., 'Nike', 'AI marketing')"),
      platform: z.enum(["twitter", "instagram", "linkedin", "facebook", "tiktok"]).optional().describe("Platform to focus on (analyzes all if omitted)")
    },
    async (params) => {
      const result = await scoreEngagement({ ...params, tier });
      return { content: [{ type: "text", text: result }] };
    }
  );

  server.tool(
    "detect_trends",
    "Detect trending topics and conversations in a niche — viral content patterns, emerging topics, sentiment shifts, and opportunity alerts.",
    {
      niche: z.string().describe("Industry or niche to monitor (e.g., 'AI marketing', 'fitness')"),
      timeframe: z.enum(["today", "this_week", "this_month"]).optional().describe("Timeframe for trend analysis (default: this_week)")
    },
    async (params) => {
      const result = await detectTrends({ ...params, tier });
      return { content: [{ type: "text", text: result }] };
    }
  );

  server.tool(
    "research_hashtags",
    "Research effective hashtags for a topic — popularity estimates, related hashtags, niche vs broad classification, and recommended hashtag sets.",
    {
      topic: z.string().describe("Topic or keyword for hashtag research (e.g., 'real estate', 'fitness')"),
      platform: z.enum(["instagram", "twitter", "tiktok", "linkedin"]).optional().describe("Target platform for hashtag optimization"),
      count: z.number().min(1).max(50).optional().describe("Number of hashtags to return (default: 20, max: 50)")
    },
    async (params) => {
      const result = await researchHashtags({ ...params, tier });
      return { content: [{ type: "text", text: result }] };
    }
  );

  // --- Pro/Business tier tools ---
  const PRO_TIERS = ["pro", "business"];
  const upgradeMsg = (toolName: string) =>
    `🔒 ${toolName} requires a Pro or Business tier subscription.\n\nUpgrade at https://social.ezbizservices.com/pricing to unlock advanced social media tools including content calendars, competitor benchmarks, and more.`;

  // Tool 5: Content Calendar (Pro+)
  server.tool(
    "content_calendar",
    "🔒 [Pro] Generate a detailed social media content calendar — specific posts with captions, hashtags, optimal timing, and content templates for 1-4 weeks.",
    {
      business_or_niche: z.string().describe("Business name or niche (e.g., 'fitness brand', 'Acme Plumbing')"),
      platforms: z.string().optional().describe("Comma-separated platforms (default: 'instagram,twitter,linkedin')"),
      duration: z.enum(["1_week", "2_weeks", "1_month"]).optional().describe("Calendar duration (default: 2_weeks)")
    },
    async (params) => {
      if (!PRO_TIERS.includes(tier)) {
        return { content: [{ type: "text", text: upgradeMsg("Content Calendar") }] };
      }
      const result = await generateContentCalendar({ ...params, tier });
      return { content: [{ type: "text", text: result }] };
    }
  );

  // Tool 6: Competitor Benchmarks (Pro+)
  server.tool(
    "competitor_benchmarks",
    "🔒 [Pro] Benchmark your social media against competitors — side-by-side comparison of engagement, content strategy, audience growth, and competitive gaps.",
    {
      brand: z.string().describe("Your brand name"),
      competitors: z.string().describe("Comma-separated competitor names (e.g., 'Nike,Adidas,Puma')"),
      platform: z.enum(["twitter", "instagram", "linkedin", "facebook", "tiktok"]).optional().describe("Platform to focus on (analyzes all if omitted)")
    },
    async (params) => {
      if (!PRO_TIERS.includes(tier)) {
        return { content: [{ type: "text", text: upgradeMsg("Competitor Benchmarks") }] };
      }
      const result = await benchmarkCompetitors({ ...params, tier });
      return { content: [{ type: "text", text: result }] };
    }
  );

  return server;
}

// Export for Smithery tool scanning (no real credentials needed)
export function createSandboxServer() {
  return createMcpServer();
}

// --- Session management ---
const transports: Record<
  string,
  { transport: WebStandardStreamableHTTPServerTransport; apiKey: string }
> = {};

// --- Bun HTTP server (guarded for Smithery scanner compatibility) ---
// --- Stdio transport for MCP inspectors (Glama, CLI clients) ---
if (process.argv.includes("--stdio")) {
  const server = createMcpServer("free");
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
// --- Bun HTTP server (guarded for Smithery scanner compatibility) ---
else if (typeof Bun !== "undefined" && !process.env.SMITHERY_SCAN) Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);

    // Health check
    if (url.pathname === "/health") {
      return Response.json({
        status: "ok",
        server: "ezbiz-social-media",
        version: "1.0.0",
        uptime: process.uptime(),
        activeSessions: Object.keys(transports).length,
      });
    }

    // CORS headers
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-API-Key, X-Admin-Secret, Mcp-Session-Id, Accept",
      "Access-Control-Expose-Headers": "Mcp-Session-Id",
    };

    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    // --- OAuth 2.0 + PKCE for MCP clients (Claude, etc.) ---
    const oauthConfig: OAuthConfig = {
      issuerUrl: "https://social.ezbizservices.com",
      serverName: "EzBiz Social Media Analytics",
      validateKey: validateApiKey,
      corsHeaders,
    };
    const oauthResponse = await handleOAuthRoute(req, url, oauthConfig);
    if (oauthResponse) return oauthResponse;

    const ADMIN_SECRET = process.env.ADMIN_SECRET;

    // --- API Key Management Endpoints ---
    if (url.pathname === "/api/keys/signup" && req.method === "POST") {
      try {
        const body = await req.json();
        const { name, email } = body;
        if (!email || !name) {
          return Response.json({ error: "name and email required" }, { status: 400, headers: corsHeaders });
        }
        const existing = await getKeyByEmail(email);
        if (existing) {
          const month = new Date().toISOString().slice(0, 7);
          const used = existing.data.usage[month] || 0;
          const limit = TIER_LIMITS[existing.data.tier] || 10;
          return Response.json({
            key: existing.key,
            tier: existing.data.tier,
            limit,
            used,
            recovered: true,
          }, { headers: corsHeaders });
        }
        const key = await createApiKey(name, "free", email);
        await log("info", `New free signup: ${email}`, { name });
        return Response.json({ key, tier: "free", limit: TIER_LIMITS.free }, { headers: corsHeaders });
      } catch (err: any) {
        return Response.json({ error: err.message }, { status: 500, headers: corsHeaders });
      }
    }

    if (url.pathname === "/api/keys/provision" && req.method === "POST") {
      const adminSecret = req.headers.get("x-admin-secret");
      if (adminSecret !== ADMIN_SECRET) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        const { name, email, tier } = body;
        if (!email || !tier) {
          return Response.json({ error: "email and tier required" }, { status: 400, headers: corsHeaders });
        }
        const existing = await getKeyByEmail(email);
        if (existing) {
          await upgradeKey(email, tier as Tier);
          await log("info", `Upgraded ${email} to ${tier}`, { name });
          return Response.json({
            key: existing.key,
            tier,
            limit: TIER_LIMITS[tier],
            upgraded: true,
          }, { headers: corsHeaders });
        }
        const key = await createApiKey(name || email, tier as Tier, email);
        await log("info", `Provisioned ${tier} key for ${email}`, { name });
        return Response.json({ key, tier, limit: TIER_LIMITS[tier], upgraded: false }, { headers: corsHeaders });
      } catch (err: any) {
        return Response.json({ error: err.message }, { status: 500, headers: corsHeaders });
      }
    }

    if (url.pathname === "/api/keys/usage" && req.method === "GET") {
      const key = url.searchParams.get("key") || req.headers.get("x-api-key");
      if (!key) {
        return Response.json({ error: "key required" }, { status: 400, headers: corsHeaders });
      }
      const usage = await getKeyUsage(key);
      if (!usage) {
        return Response.json({ error: "Invalid key" }, { status: 404, headers: corsHeaders });
      }
      return Response.json(usage, { headers: corsHeaders });
    }

    if (url.pathname === "/api/pricing") {
      return Response.json({
        tiers: Object.entries(TIER_LIMITS).map(([tier, limit]) => ({
          tier,
          price: TIER_PRICES[tier],
          requestsPerMonth: limit,
        })),
      }, { headers: corsHeaders });
    }

    // MCP endpoint — accept on /mcp and also on / for POST (Smithery/scanners)
    if (url.pathname === "/mcp" || (url.pathname === "/" && req.method === "POST")) {
      const sessionId = req.headers.get("mcp-session-id");

      // --- GET/DELETE: session-based operations (SSE stream / session close) ---
      // Part of the MCP Streamable HTTP protocol. Session was authenticated during POST.
      if (req.method === "GET") {
        if (sessionId && transports[sessionId]) {
          console.log(`[MCP] GET SSE stream | session: ${sessionId}`);
          return transports[sessionId].transport.handleRequest(req);
        }
        return Response.json(
          { jsonrpc: "2.0", error: { code: -32000, message: "Bad request: GET requires a valid mcp-session-id. Start with POST." }, id: null },
          { status: 400, headers: corsHeaders }
        );
      }

      if (req.method === "DELETE") {
        if (sessionId && transports[sessionId]) {
          console.log(`[MCP] DELETE session | session: ${sessionId}`);
          return transports[sessionId].transport.handleRequest(req);
        }
        return Response.json(
          { jsonrpc: "2.0", error: { code: -32000, message: "Session not found" }, id: null },
          { status: 404, headers: corsHeaders }
        );
      }

      // --- POST: API key auth (accept from multiple sources for proxy compatibility) ---
      const bearerToken = req.headers.get("authorization")?.replace(/^Bearer\s+/i, "");
      const apiKey =
        req.headers.get("x-api-key") ||
        req.headers.get("apikey") ||
        url.searchParams.get("api_key") ||
        url.searchParams.get("apiKey") ||
        url.searchParams.get("apikey") ||
        bearerToken;

      // Debug logging
      const qp = url.search || "none";
      console.log(`[MCP] POST ${url.pathname} | auth: ${bearerToken ? "Bearer " + bearerToken.slice(0, 12) + "..." : "none"} | x-api-key: ${req.headers.get("x-api-key") ? "yes" : "no"} | apikey-hdr: ${req.headers.get("apikey") ? "yes" : "no"} | query: ${qp} | session: ${sessionId || "none"}`);

      // Validate API key (if provided). Initialize is allowed without auth
      // so MCP inspectors (Glama, etc.) can verify the server and discover tools.
      // Tool calls still require a valid API key.
      const authResult = apiKey ? await validateApiKey(apiKey) : { valid: false, tier: "free", error: "No API key" };

      // Check for existing session (POST with session ID)

      if (sessionId && transports[sessionId]) {
        const { transport } = transports[sessionId];

        if (req.method === "POST") {
          try {
            const cloned = req.clone();
            const body = await cloned.json();
            if (body?.method === "tools/call") {
              if (!apiKey || !authResult.valid) {
                return Response.json(
                  { jsonrpc: "2.0", error: { code: -32001, message: "API key required for tool calls. Get a free key at https://social.ezbizservices.com" }, id: body?.id || null },
                  { status: 401, headers: corsHeaders }
                );
              }
              await recordUsage(apiKey);
            }
          } catch {}
        }

        return transport.handleRequest(req);
      }

      if (req.method === "POST") {
        // For non-initialize requests without auth, return 401 with OAuth hint
        if (!authResult.valid && apiKey) {
          console.log(`[MCP] AUTH FAILED: ${authResult.error} | key: ${apiKey.slice(0, 12)}...`);
          return new Response(JSON.stringify({
              jsonrpc: "2.0",
              error: { code: -32001, message: authResult.error },
              id: null,
            }), {
              status: 401,
              headers: { "Content-Type": "application/json", ...corsHeaders },
            }
          );
        }

        try {
          const tier = authResult.valid ? (authResult.tier || "free") : "free";
          const transport = new WebStandardStreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            onsessioninitialized: (sid: string) => {
              transports[sid] = { transport, apiKey: apiKey || "" };
              log("info", `New MCP session: ${sid}`, {
                tier,
                name: authResult.valid ? authResult.name : "anonymous",
              });
            },
            onsessionclosed: (sid: string) => {
              delete transports[sid];
              log("info", `Session closed: ${sid}`);
            },
            enableJsonResponse: true,
          });

          const mcpServer = createMcpServer(tier);
          await mcpServer.connect(transport);

          // Record init usage only for authenticated sessions
          if (apiKey && authResult.valid) await recordUsage(apiKey);

          return transport.handleRequest(req);
        } catch (err: any) {
          await log("error", `MCP init error: ${err.message}`, { stack: err.stack });
          return Response.json(
            {
              jsonrpc: "2.0",
              error: { code: -32603, message: "Internal server error" },
              id: null,
            },
            { status: 500 }
          );
        }
      }

      return Response.json(
        {
          jsonrpc: "2.0",
          error: {
            code: -32000,
            message: "Bad request: send a POST with initialize to start a session.",
          },
          id: null,
        },
        { status: 400 }
      );
    }

    // Static files
    // Serve sitemap and robots from static dir
    if (url.pathname === "/sitemap.xml" || url.pathname === "/robots.txt") {
      const staticRes = await serveStatic("/static" + url.pathname);
      if (staticRes) return staticRes;
    }

    if (url.pathname.startsWith("/static/") || url.pathname.startsWith("/.well-known/")) {
      const staticRes = await serveStatic(url.pathname);
      if (staticRes) return staticRes;
    }

    // Pages
    const PAGE_ROUTES: Record<string, string> = {
      "/": "index.html",
      "/docs": "docs.html",
      "/signup": "signup.html",
      "/pricing": "pricing.html",
      "/tools/analyze-profile": "tools/analyze-profile.html",
      "/tools/score-engagement": "tools/score-engagement.html",
      "/tools/detect-trends": "tools/detect-trends.html",
      "/tools/research-hashtags": "tools/research-hashtags.html",
    };

    // Check static page routes first
    const pageName = PAGE_ROUTES[url.pathname];
    if (pageName) {
      try {
        const html = await loadPage(pageName);
        return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
      } catch (err: any) {
        await log("error", `Page load error: ${pageName} - ${err.message}`);
        return new Response("Page not found", { status: 500 });
      }
    }

    // Dynamic blog routes: /blog → index, /blog/[slug] → blog post
    if (url.pathname === "/blog" || url.pathname === "/blog/") {
      try {
        const html = await loadPage("blog/index.html");
        return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
      } catch (err: any) {
        await log("error", `Blog index error: ${err.message}`);
        return new Response("Blog not found", { status: 404 });
      }
    }

    if (url.pathname.startsWith("/blog/")) {
      const slug = url.pathname.replace("/blog/", "");
      if (slug && /^[a-z0-9-]+$/.test(slug)) {
        try {
          const html = await loadPage(`blog/${slug}.html`);
          return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
        } catch (err: any) {
          return new Response("Post not found", { status: 404 });
        }
      }
    }

    return new Response("Not found", { status: 404 });
  },
});

if (typeof Bun !== "undefined" && !process.env.SMITHERY_SCAN && !process.argv.includes("--stdio")) console.log(`MCP Social Media Analytics server running on port ${PORT}`);

process.on("SIGINT", async () => {
  console.log("Shutting down...");
  for (const sid in transports) {
    try {
      await transports[sid].transport.close();
    } catch {}
    delete transports[sid];
  }
  process.exit(0);
});
