# Ledger signing

How a disposition layer's Merkle root is signed, what the signature covers,
when it is produced, who needs the key, and how to verify. The mechanism lives
in `traust-ledger` (`traust_ledger` integrity module); this page is the harness-side
contract. Provider-level setup for identity signing is traust-ledger's
documentation (`traust-ledger/docs/auth.md` and `traust-ledger/docs/ledger-integrity.md`).

Signing proves the **ledger's** integrity. It is distinct from verifying **who
a human signer is** at countersign time; that is authentication, documented
with `traust auth` ([setup](setup.md)).

## What is signed

**The ledger layer file, `<repo>-findings-layer.json`, and nothing else.**
Audit reports, cumulative reports, triage, threat models, and verification
reports are not signed; the layer binds them by content hash instead.

One signature per layer file, stored inside the file it signs, as three
sibling keys in `metadata`: `merkle_root_signature` (a Sigstore bundle
serialised as a JSON string), `merkle_signing_method` (`keypair` or
`identity`), and `merkle_signature_format`.

cosign does not sign the file. It signs a SHA-256 digest over a canonical
document (`merkle_signature_payload`). The current format is **4**; each
format is a superset of the previous, and the verifier reconstructs the payload
for whichever format a layer was signed under:

| Format | Payload adds | Closes |
|---|---|---|
| 1 | `merkle_root` | — (transplantable onto any layer with the same root) |
| 2 | `leaf_format`, `merkle_epoch`, `merkle_size`, `pre_merkle_checkpoint`, digest of `claim_hashes` | replay after rollback; re-scoping by editing epoch or format; baseline claim substitution |
| 3 | `audit_report_sha256` | pointing a layer at a substituted report by rewriting its digest |
| 4 | digest of `artifact_digests` | unverifiable sibling artifacts after a move to object storage |

The chain of custody: event content → Merkle leaf (canonical JSON of the whole
event, `leaf_format` 2) → `merkle_root` → signed digest → signature. Edit an
event and the root breaks; edit the root and the signature breaks; edit the
annotated report or any digested sibling and the signature breaks. Because the
digest is computed from parsed values, re-serialising a layer never breaks its
signature.

## When it is signed

**On every write to a layer, automatically, in the same call that stamps it.**
Every ledger writer calls `stamp_and_sign(layer)` immediately before
serialising: recompute the Merkle root, then sign it if a key is configured.
Signing a stale root is impossible by construction.

A scan does not sign anything by itself. A finding reaches the ledger as a
disposition event, and that event causes the write, the stamp, and the
signature. The legacy layer writers are the triage and validation event emitters,
the cumulative-report rebuild, and the two findings routers. `rebaseline()` is
the exception: it re-points a layer's `audit_report` and leaves stamping to the
next recording write. The ported direct severity recorder calls core services;
it does not serialize, stamp or sign a legacy layer file.

A write that moves the root **drops a signature it cannot renew**. If the
recomputed root differs and no key is configured, the stale signature and its
method and format keys are removed rather than left behind as something that
would fail verification and look like tampering. The attempt reports
`stale_signature_dropped`, and writers print the warning. A re-stamp that yields
the same root leaves a valid signature alone.

Three outcomes, none silent:

| `SignAttempt.status` | Meaning | Writer behaviour |
|---|---|---|
| `signed` | key present, cosign succeeded | signature written |
| `unconfigured` | no key (or, for identity, no token) | layer stamped and written unsigned; expected only where the key is deliberately absent |
| `failed` | key present, signing broke | warns on stderr; a configured-but-broken signer never degrades quietly |

Enforcement is configuration: `traust.yaml` → `ledger.required: true` makes an
unsigned root a fail-closed ERROR at verification and makes the harness refuse
to write a layer it cannot sign.

## Per-layer signing versus checkpoint signing

Today every layer is its own append-only log with its own root, signed whole
on every write; that is cheap because writes are infrequent. The layer format
also carries `merkle_epoch` and `pre_merkle_checkpoint` for a checkpoint model,
in which a single high-throughput log signs periodic checkpoints and a
just-written event is durable but not yet attested. That model is implemented
in the format and unused: every layer sits at `merkle_epoch: 0`, meaning the
tree covers every event in the array. Both fields are inside the signed
payload, so a signature cannot be re-scoped by editing them.

## Who needs the key

The private key is needed at exactly one operation: signing a root.

| Operation | Key needed |
|---|---|
| Compute or stamp a fingerprint, append an event, stamp the Merkle root | none — hashing |
| Verify root against events (tamper check) | none — recompute and compare |
| **Sign the root** (write path or bulk) | **private key** |
| Verify a signature | **public key only** |
| Enforce "must be signed" (`traust.yaml` → `ledger.required`) | none — policy |

Consequences:

- A scanner or audit run never needs the key. It appends and stamps, producing
  a valid, rooted, schema-clean but unsigned layer. A worker that processes
  untrusted content stays keyless by design; the key belongs only to the
  component that owns the ledger write path.
- Reading and verifying the ledger needs no secret. The public half is the file
  `ledger.public_key_path` in `traust.yaml` names; anyone who can read the corpus
  and that file can verify every signature.
- An unsigned root detects accidents, not adversaries: an edit, a deletion, a
  reorder. It does not stop someone who can edit the file from re-stamping it.
  The signature closes that gap, which is why "stamped" and "signed" are
  separate properties.

## Configuration

Harness signing is deployment configuration: the `ledger:` section of
`$TRAUST_CONFIG_HOME/traust.yaml` (traust-contracts' `traust` schema; template:
`config/traust.example.yaml`). traust-core reads it into `LedgerConfig`, so **no
`LAAS_SIGNING_*` variable affects a harness run** — mount the config instead.
Without a `ledger:` section the harness writes unsigned layers and does not require
signatures.

The method is a cosign key pair, recommended for air-gapped or disconnected
environments: the public half sits beside the config, the private half and its
passphrase live in the deployment's secret store and are mounted only into the
write-path job. Keyless (OIDC/sigstore identity) signing is not yet a traust-core
option.

| `traust.yaml` key | Meaning |
|---|---|
| `ledger.key_path` | path of the private key; required when `required` is true |
| `ledger.public_key_path` | the public key signatures verify against |
| `ledger.previous_public_key_path` | during a rotation, so old signatures still verify |
| `ledger.required` | refuse to write an unsigned layer, and treat an unsigned root as a verification ERROR |
| _(secret, never in config)_ `COSIGN_PASSWORD` | the key passphrase, read by cosign from the environment where it runs |

Where the key lives, operationally: mounted from the secret store into the job
that runs the ledger writers, at the path `ledger.key_path` names, with the
passphrase exported as `COSIGN_PASSWORD`. Not on every machine that runs a scan.

The standalone `ledger` CLI (`ledger sign`, `ledger verify`, below) is the
Ledger's own tool and still reads its `LAAS_SIGNING_*` environment or flags.

## Commands

```bash
# sign one layer (keypair)
ledger sign <layer>.json --key /path/to/cosign.key
# identity method
ledger sign <layer>.json --method identity --oidc-issuer <url> --expected-identity <san>
# verify one layer's signature
ledger verify-signature <layer>.json --key /etc/traust/cosign.pub   # ledger.public_key_path
# Merkle integrity plus signature, one file or the whole store
ledger verify --path <layer>.json --check-signatures
ledger verify --all --check-signatures

```

`ledger` is the console script installed by traust-ledger. `--rekor` on `sign`
uploads the signature to a transparency log; it is opt-in and off by default.

`traust reporting validate` checks artifact structure and semantic consistency;
it does not verify stored ledger proofs or accept a signing-key option.
Use core's `Context.services().ledger.verify(layer_id)` for a stored layer's
integrity and signature verification. The standalone file commands above do not
replace that domain service.

## cosign v3 behaviour that matters

- The signature is a **Sigstore bundle**, not a bare signature: cosign v3
  writes bundles to a file, so the backend round-trips through a temporary
  directory and compacts the JSON to one line for layer metadata.
- **No public transparency log by default.** cosign v3 would otherwise upload
  every ledger write to the public log, publishing the timing of every write to
  an irrevocable record and making signing depend on that service. The backend
  passes `--use-signing-config=false --tlog-upload=false` unless `--rekor` is
  requested; a regression test asserts emitted bundles carry no `tlogEntries`.
- Verification accepts both the bundle and the older bare-signature form, so
  layers signed under the earlier contract remain verifiable; bundle
  verification passes `--insecure-ignore-tlog`, which is correct because the
  bundle deliberately carries no log entry and integrity comes from the key.

## Rotation

Generate a new pair; write private key, passphrase, and public key to the
secret store together; replace the public half in `TRAUST_CONFIG_HOME` and
record its fingerprint outside the repository that holds it. **Do not re-sign
historical layers** — old roots stay signed by the old key; keep the retired
public key as `ledger.previous_public_key_path` (and archived as `<name>-<date>.pub`) so
history remains verifiable, and record which key covers which period.
