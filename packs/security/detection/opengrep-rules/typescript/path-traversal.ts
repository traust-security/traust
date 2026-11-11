import fs, { createReadStream } from "fs";
import fsp from "fs/promises";
import path from "path";

export async function saveConfig(req: any, res: any): Promise<void> {
  const { config, name } = req.body;
  const filepath = path.join(CONFIGS_DIR, name);
  // ruleid: traust-ts-path-traversal-fs-taint
  await fsp.writeFile(filepath, config);
  // ok: traust-ts-path-traversal-fs-taint
  await fsp.writeFile(path.join(CONFIGS_DIR, "latest.yaml"), req.body.config);
  res.json({ ok: true });
}

export async function readLog(req: any, res: any): Promise<void> {
  const logFile = path.join(LOGS_DIR, `${req.params.id}.log`);
  // ruleid: traust-ts-path-traversal-fs-taint
  const logs = await fsp.readFile(logFile, "utf8");
  // ok: traust-ts-path-traversal-fs-taint
  const safe = await fsp.readFile(path.join(LOGS_DIR, path.basename(req.params.id)), "utf8");
  res.send(logs + safe);
}

export function servePublic(req: any, res: any): void {
  const url = req.url.split("?")[0];
  const filePath = `${publicFolder}${url}`;
  // ruleid: traust-ts-path-traversal-fs-taint
  createReadStream(filePath).pipe(res);
}

export function serve(req: any, res: any): void {
  // ruleid: traust-ts-path-traversal-fs-taint
  res.sendFile(path.join(STATIC_DIR, req.query.file));
  // ok: traust-ts-path-traversal-fs-taint
  res.sendFile(path.join(STATIC_DIR, "index.html"));
  // ok: traust-ts-path-traversal-fs-taint
  fs.readFileSync(path.join(__dirname, "template.html"), "utf8");
}
