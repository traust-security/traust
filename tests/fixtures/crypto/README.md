# Crypto-analysis fixtures

Copied from traust-core's code-facts crypto fixtures (`b553bfc`): `repo/` is a public-safe
sample checkout, `manifest-sbom.cdx.json` its syft-shaped manifest SBOM, `legacy-crypto-probe.json`
the legacy source tier's output over it (traust-engine `60d2e7e`). `image/` holds a real
`podman image inspect` and `syft` scan of ubi9-minimal; `cluster/s_client-tls13.txt` a real
`openssl s_client` transcript. No estate data.
