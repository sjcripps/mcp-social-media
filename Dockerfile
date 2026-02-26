FROM oven/bun:1-alpine

WORKDIR /app

COPY package.json ./
RUN bun install --production

COPY server.ts ./
COPY lib/ ./lib/
COPY tools/ ./tools/
COPY pages/ ./pages/
COPY static/ ./static/

ENV MCP_PORT=4202

EXPOSE 4202

CMD ["bun", "run", "server.ts"]
