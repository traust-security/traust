export function callback(req: any, res: any): void {
  // ruleid: traust-ts-open-redirect-response-taint
  res.redirect(req.query.next);
  // ruleid: traust-ts-open-redirect-response-taint
  res.redirect(302, req.query.returnTo);
  // ok: traust-ts-open-redirect-response-taint
  res.redirect("/login");
  // ruleid: traust-ts-open-redirect-response-taint
  res.setHeader("Location", req.query.next);
  const { returnTo } = req.body;
  // ruleid: traust-ts-open-redirect-response-taint
  res.redirect(returnTo);
}

export function afterLogin(): void {
  const params = new URLSearchParams(window.location.search);
  const target = params.get("redirect");
  // ruleid: traust-ts-open-redirect-client-navigation
  window.location.assign(target);
  // ok: traust-ts-open-redirect-client-navigation
  window.location.assign("/home");
  // ruleid: traust-ts-open-redirect-client-navigation
  window.open(window.location.hash.slice(1), "_blank");
  // ok: traust-ts-open-redirect-client-navigation
  window.open("/graph", params.get("target") || "_top");
}
