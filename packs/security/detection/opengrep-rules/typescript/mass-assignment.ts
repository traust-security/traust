import { Router } from "express";

const ledger = Router();

ledger.put("/accounts/:id", async (req, res) => {
  // ruleid: traust-ts-mass-assignment-request-body
  res.json(await Account.update(req.params.id, req.body));
});

ledger.post("/accounts", async (req, res) => {
  // ruleid: traust-ts-mass-assignment-request-body
  res.json(await prisma.account.create({ data: req.body }));
});

ledger.patch("/accounts/:id", async (req, res) => {
  const account = await Account.findById(req.params.id);
  // ruleid: traust-ts-mass-assignment-request-body
  Object.assign(account, req.body);
  // ruleid: traust-ts-mass-assignment-request-body
  const draft = new Account(req.body);
  res.json([account, draft]);
});

ledger.patch("/accounts/:id/label", async (req, res) => {
  // ok: traust-ts-mass-assignment-request-body
  res.json(await Account.update(req.params.id, { label: req.body.label }));
});

ledger.post("/search", async (req, res) => {
  // ok: traust-ts-mass-assignment-request-body
  const q = new URLSearchParams(req.body);
  res.json(q.toString());
});
