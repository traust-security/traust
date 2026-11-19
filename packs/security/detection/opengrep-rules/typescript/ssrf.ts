import axios from "axios";

export async function proxy(req: any, res: any): Promise<void> {
  const target = req.query.endpoint;
  // ruleid: traust-ts-ssrf-request-taint
  await fetch(target);

  // ruleid: traust-ts-ssrf-request-taint
  await axios.get(`https://${req.params.cluster}/api/v1/status`);

  // ok: traust-ts-ssrf-request-taint
  await fetch("https://api.openshift.com/healthz");

  // ruleid: traust-ts-ssrf-request-taint
  await got.get(req.body.webhookUrl);

  // ruleid: traust-ts-ssrf-request-taint
  https.request(req.query.callback, () => undefined);

  // ruleid: traust-ts-ssrf-request-taint
  await axios.request({ url: req.body.target });
}

export async function forward(req: any): Promise<void> {
  const origin = new URL(req.headers.referer).origin;
  // ruleid: traust-ts-ssrf-request-taint
  await fetch(`${origin}${req.path}`);
  const { host } = req.query;
  // ruleid: traust-ts-ssrf-request-taint
  await axios.get(`https://${host}/healthz`);
}

export async function forwardPayload(req: { body: { message: string }; query: { url: string } }): Promise<void> {
  // A tainted body or header does not change a fixed destination.
  // ok: traust-ts-ssrf-request-taint
  await fetch("https://api.example.org/events", { method: "POST", body: req.body.message });
  // ok: traust-ts-ssrf-request-taint
  await axios.post("https://api.example.org/events", req.body.message);
  // ok: traust-ts-ssrf-request-taint
  await axios.request({ url: "https://api.example.org/events", data: req.body.message });
  // ok: traust-ts-ssrf-request-taint
  await axios({ url: "https://api.example.org/events", headers: { "X-Message": req.body.message } });
  // ruleid: traust-ts-ssrf-request-taint
  await axios({ url: req.query.url, data: req.body.message });
  // ruleid: traust-ts-ssrf-request-taint
  await axios.request({ baseURL: req.query.url, url: "/events" });
  // ruleid: traust-ts-ssrf-request-taint
  await needle("post", req.query.url, req.body.message);
  // ok: traust-ts-ssrf-request-taint
  await needle("post", "https://api.example.org/events", req.body.message);
}
