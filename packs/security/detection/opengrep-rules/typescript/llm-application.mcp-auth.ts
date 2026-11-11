import { requireBearerAuth } from "@modelcontextprotocol/express";
import { NodeStreamableHTTPServerTransport } from "@modelcontextprotocol/node";
import { McpServer } from "@modelcontextprotocol/server";
import express from "express";

declare const verifier: unknown;
const server = new McpServer({ name: "orders", version: "1.0.0" });
const app = express();

app.post("/mcp", requireBearerAuth({ verifier }), async (req, res) => {
  // ok: traust-ts-llm-application-mcp-http-without-auth
  const transport = new NodeStreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});
