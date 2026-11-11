import jwt from "jsonwebtoken";

export function check(token: string, key: string) {
  // ruleid: traust-ts-authentication-jwt-verification-weakened
  const a = jwt.verify(token, key, { algorithms: ["HS256", "none"] });
  // ruleid: traust-ts-authentication-jwt-verification-weakened
  const b = jwt.verify(token, key, { ignoreExpiration: true });
  // ok: traust-ts-authentication-jwt-verification-weakened
  const c = jwt.verify(token, key, { algorithms: ["RS256"] });
  return [a, b, c];
}
