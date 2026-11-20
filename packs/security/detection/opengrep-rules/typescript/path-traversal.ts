import fs, { createReadStream } from "fs";
import fsp from "fs/promises";
import path from "path";
import sanitize from "sanitize-filename";
import sanitizeFilename from "sanitize-filename";
import { default as sanitizeDefault } from "sanitize-filename";
import unrelatedSanitize from "./unrelated-sanitizer";
import { sanitize as namedSanitize } from "sanitize-filename";

const sanitizeCommonJs = require("sanitize-filename");

type FileRequest = {
  params: { id: string };
  query: { override: string; filename: string };
};

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

export async function readCleanedName(req: { params: { id: string } }): Promise<void> {
  function sanitize(value: string): string {
    // Shadowing a package import with whitespace cleanup is still unsafe.
    return value.trim();
  }

  // ruleid: traust-ts-path-traversal-fs-taint
  await fsp.readFile(path.join(LOGS_DIR, sanitize(req.params.id)), "utf8");
  // ok: traust-ts-path-traversal-fs-taint
  await fsp.readFile(path.join(LOGS_DIR, path.basename(sanitize(req.params.id))), "utf8");
}

export async function readPackageSanitized(req: FileRequest): Promise<void> {
  // ok: traust-ts-path-traversal-fs-taint
  await fsp.readFile(path.join(LOGS_DIR, sanitize(req.params.id)), "utf8");
  // ok: traust-ts-path-traversal-fs-taint
  await fsp.readFile(path.join(LOGS_DIR, sanitizeFilename(req.params.id)), "utf8");
  // ok: traust-ts-path-traversal-fs-taint
  await fsp.readFile(path.join(LOGS_DIR, sanitizeDefault(req.params.id)), "utf8");
  // ok: traust-ts-path-traversal-fs-taint
  await fsp.readFile(path.join(LOGS_DIR, sanitizeCommonJs(req.params.id)), "utf8");
}

export async function readCommonJsAlias(req: FileRequest): Promise<void> {
  const sanitize = require("sanitize-filename");
  // ok: traust-ts-path-traversal-fs-taint
  await fsp.readFile(path.join(LOGS_DIR, sanitize(req.params.id)), "utf8");
}

export async function readUnrelatedPackage(req: FileRequest): Promise<void> {
  // ruleid: traust-ts-path-traversal-fs-taint
  await fsp.readFile(path.join(LOGS_DIR, unrelatedSanitize(req.params.id)), "utf8");
  // Named exports are not the package's documented default sanitizer binding.
  // ruleid: traust-ts-path-traversal-fs-taint
  await fsp.readFile(path.join(LOGS_DIR, namedSanitize(req.params.id)), "utf8");
}

export async function readShadowedParameter(
  req: FileRequest,
  sanitizeFilename: (value: string) => string,
): Promise<void> {
  // ruleid: traust-ts-path-traversal-fs-taint
  await fsp.readFile(path.join(LOGS_DIR, sanitizeFilename(req.params.id)), "utf8");
}

export async function readShadowedCommonJs(req: FileRequest): Promise<void> {
  const sanitizeCommonJs = (value: string): string => value.trim();
  // ruleid: traust-ts-path-traversal-fs-taint
  await fsp.readFile(path.join(LOGS_DIR, sanitizeCommonJs(req.params.id)), "utf8");
}

export async function readLocalSanitizeFilename(req: FileRequest): Promise<void> {
  function sanitizeFilename(value: string): string {
    return value.trim();
  }
  // ruleid: traust-ts-path-traversal-fs-taint
  await fsp.readFile(path.join(LOGS_DIR, sanitizeFilename(req.params.id)), "utf8");
}

export async function readReassignedCommonJs(req: FileRequest): Promise<void> {
  let sanitize = require("sanitize-filename");
  sanitize = (value: string): string => value.trim();
  // ruleid: traust-ts-path-traversal-fs-taint
  await fsp.readFile(path.join(LOGS_DIR, sanitize(req.params.id)), "utf8");
}

export async function readChangedAfterSanitizing(req: FileRequest): Promise<void> {
  let filename = sanitize(req.params.id);
  filename = req.query.override;
  // ruleid: traust-ts-path-traversal-fs-taint
  await fsp.readFile(path.join(LOGS_DIR, filename), "utf8");
}

export async function readMutableDestructuredName(req: FileRequest): Promise<void> {
  let { filename } = req.query;
  // ruleid: traust-ts-path-traversal-fs-taint
  await fsp.readFile(path.join(LOGS_DIR, filename), "utf8");
}
