class TokenFilter {
    Claims claims(String token) {
        // ruleid: traust-java-authentication-jwt-unsigned-parse
        Claims a = Jwts.parser().parseClaimsJwt(token).getBody();
        // ruleid: traust-java-authentication-jwt-unsigned-parse
        Object b = Jwts.parser().setSigningKey(key).parse(token).getBody();
        // ruleid: traust-java-authentication-jwt-unsigned-parse
        String user = JWT.decode(token).getSubject();
        // ok: traust-java-authentication-jwt-unsigned-parse
        Claims c = Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();
        // ok: traust-java-authentication-jwt-unsigned-parse
        DecodedJWT d = JWT.require(Algorithm.RSA256(publicKey, null)).build().verify(token);
        return c;
    }
}
