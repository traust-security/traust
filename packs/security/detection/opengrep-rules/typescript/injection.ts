import { exec, execFile, execSync } from "child_process";
import childProcess from "child_process";

export function handler(req: any, res: any): void {
  const slug = req.query.repositorySlug;
  // ruleid: traust-ts-injection-child-process-taint
  exec(`exhort analyze ${slug}`);

  const cmd = `exhort stack ${req.query.manifestFilePath} --summary`;
  // ruleid: traust-ts-injection-child-process-taint
  childProcess.exec(cmd, () => undefined);

  // ok: traust-ts-injection-child-process-taint
  /pattern/.exec(slug);

  // ruleid: traust-ts-injection-child-process-taint
  execSync("scan --path " + req.body.manifestFilePath);

  // ok: traust-ts-injection-child-process-taint
  execFile("exhort", ["analyze", slug]);

  // ok: traust-ts-injection-child-process-taint
  execSync("npm audit --json");
}

export function dynamicEval(req: any): void {
  // ruleid: traust-ts-injection-eval-taint
  eval(req.query.expr);

  // ok: traust-ts-injection-eval-taint
  eval("1 + 1");
}
