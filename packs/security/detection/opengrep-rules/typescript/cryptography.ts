import https from "https";

export function clients(url: string): void {
  // ruleid: traust-ts-cryptography-reject-unauthorized-false
  const agent = new https.Agent({ rejectUnauthorized: false });

  // ruleid: traust-ts-cryptography-reject-unauthorized-false
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

  // ok: traust-ts-cryptography-reject-unauthorized-false
  const safeAgent = new https.Agent({ keepAlive: true });
  void agent;
  void safeAgent;
}

export function tokens(password: string, data: Buffer, key: Buffer) {
  // ruleid: traust-ts-cryptography-weak-random-secret
  const resetToken = Math.random().toString(36).slice(2);
  // ok: traust-ts-cryptography-weak-random-secret
  const jitter = Math.random() * 100;
  // ruleid: traust-ts-cryptography-weak-hash
  const stored = crypto.createHash("md5").update(password).digest("hex");
  // ok: traust-ts-cryptography-weak-hash
  const digest = crypto.createHash("sha256").update(data).digest("hex");
  // ruleid: traust-ts-cryptography-weak-cipher
  const legacy = crypto.createCipher("aes192", password);
  // ruleid: traust-ts-cryptography-weak-cipher
  const ecb = crypto.createCipheriv("aes-256-ecb", key, null);
  // ok: traust-ts-cryptography-weak-cipher
  const gcm = crypto.createCipheriv("aes-256-gcm", key, iv);
  return [resetToken, jitter, stored, digest, legacy, ecb, gcm];
}
