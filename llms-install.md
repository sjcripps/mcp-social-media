# Installing Social Media Analytics MCP Server

This is a hosted MCP server — no local installation needed.

## Setup (30 seconds)

1. Get a free API key: https://social.ezbizservices.com/signup
2. Add this to your MCP client configuration:

```json
{
  "mcpServers": {
    "social-media": {
      "url": "https://social.ezbizservices.com/mcp",
      "headers": {
        "x-api-key": "YOUR_API_KEY"
      }
    }
  }
}
```

## Available Tools

- `analyze_profile` — Social media profile and brand analysis across platforms
- `content_calendar` — Content calendar generation with posting schedule
- `hashtag_research` — Hashtag analysis with reach, engagement, and niche classification
- `engagement_analytics` — Engagement scoring with benchmarks and trend detection

## Requirements

- Any MCP-compatible client (Claude Desktop, Cursor, Cline, Windsurf, etc.)
- Free API key (no credit card required)
