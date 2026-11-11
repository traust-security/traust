import { exec } from "child_process";
import OpenAI from "openai";
import Anthropic from "@anthropic-ai/sdk";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { NodeStreamableHTTPServerTransport } from "@modelcontextprotocol/node";
import { SSEServerTransport, StdioServerTransport, type Transport } from "@modelcontextprotocol/server";

const client = new OpenAI();
const claude = new Anthropic();
const server = new McpServer({ name: "orders", version: "1.0.0" });

declare const db: { query(sql: string, params?: unknown[]): Promise<unknown> };

export async function runSuggestion(question: string) {
  const reply = await client.chat.completions.create({
    model: "m",
    messages: [{ role: "user", content: question }],
  });
  const command = reply.choices[0].message.content ?? "";
  // ruleid: traust-ts-llm-application-output-to-shell-taint
  exec(command);

  // ok: traust-ts-llm-application-output-to-shell-taint
  exec("uptime");
}

export async function evaluate(question: string) {
  const msg = await claude.messages.create({
    model: "m",
    max_tokens: 100,
    messages: [{ role: "user", content: question }],
  });
  const expression = msg.content[0].text;
  // ruleid: traust-ts-llm-application-output-to-code-exec-taint
  return eval(expression);
}

export async function askDatabase(question: string) {
  const reply = await client.chat.completions.create({
    model: "m",
    messages: [{ role: "user", content: question }],
  });
  const sql = reply.choices[0].message.content ?? "";
  // ruleid: traust-ts-llm-application-output-to-sql-taint
  await db.query(sql);

  // ok: traust-ts-llm-application-output-to-sql-taint
  await db.query("SELECT name FROM products WHERE label = $1", [sql]);
}

export function mountMcp(app: { post(path: string, h: unknown): void }) {
  app.post("/mcp", async (req: unknown, res: unknown) => {
    // ruleid: traust-ts-llm-application-mcp-http-without-auth
    const transport = new NodeStreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    await server.connect(transport);
  });
  app.post("/sse", async (req: unknown, res: unknown) => {
    // ruleid: traust-ts-llm-application-mcp-http-without-auth
    const transport = new SSEServerTransport("/messages", res);
    await server.connect(transport);
  });
}

export class LoggingTransport implements Transport {
  private inner: NodeStreamableHTTPServerTransport;
  constructor() {
    // ok: traust-ts-llm-application-mcp-http-without-auth
    this.inner = new NodeStreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  }
}

export async function serveLocal() {
  // ok: traust-ts-llm-application-mcp-http-without-auth
  await server.connect(new StdioServerTransport());
}

export async function research(question: string) {
  const messages = [{ role: "user" as const, content: question }];
  // ruleid: traust-ts-llm-application-unbounded-agent-loop
  while (true) {
    const reply = await client.chat.completions.create({ model: "m", messages });
    const text = reply.choices[0].message.content ?? "";
    if (text.startsWith("DONE")) {
      return text;
    }
  }
}

export async function boundedResearch(question: string, maxSteps = 8) {
  const messages = [{ role: "user" as const, content: question }];
  let steps = 0;
  // ok: traust-ts-llm-application-unbounded-agent-loop
  while (true) {
    steps += 1;
    if (steps > maxSteps) {
      return null;
    }
    const reply = await client.chat.completions.create({ model: "m", messages });
    if ((reply.choices[0].message.content ?? "").startsWith("DONE")) {
      return reply;
    }
  }
}
