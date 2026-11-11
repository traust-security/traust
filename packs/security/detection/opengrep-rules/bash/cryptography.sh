#!/bin/bash
# Test fixture for bash/cryptography.yaml

# ruleid: traust-bash-cryptography-cosign-classical-signing
cosign sign --key cosign.key "$IMAGE"

# ruleid: traust-bash-cryptography-cosign-classical-signing
cosign sign-blob --key env://COSIGN_KEY release.tar.gz

# ruleid: traust-bash-cryptography-cosign-classical-signing
cosign attest --predicate sbom.json "$IMAGE"

# ruleid: traust-bash-cryptography-cosign-classical-signing
cosign generate-key-pair k8s://ns/secret

# ok: traust-bash-cryptography-cosign-classical-signing
cosign verify --key cosign.pub "$IMAGE"

# ok: traust-bash-cryptography-cosign-classical-signing
echo "we use sigstore for signing; see docs/cosign.md"
