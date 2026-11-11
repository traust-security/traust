package com.example.ledger;

import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;

// ruleid: traust-java-cors-any-origin-with-credentials
@CrossOrigin(originPatterns = "*", allowCredentials = "true")
class StatementController {}

// ok: traust-java-cors-any-origin-with-credentials
@CrossOrigin(originPatterns = "https://*.example.org", allowCredentials = "true")
class PartnerController {}

// ok: traust-java-cors-any-origin-with-credentials
@CrossOrigin(originPatterns = "*")
class PublicController {}

class CorsSetup {
    CorsConfiguration open() {
        CorsConfiguration c = new CorsConfiguration();
        // ruleid: traust-java-cors-any-origin-with-credentials
        c.addAllowedOriginPattern("*");
        c.setAllowCredentials(true);
        return c;
    }

    CorsConfiguration listed() {
        CorsConfiguration c = new CorsConfiguration();
        // ruleid: traust-java-cors-any-origin-with-credentials
        c.setAllowedOriginPatterns(List.of("*"));
        c.setAllowCredentials(true);
        return c;
    }

    CorsConfiguration anonymous() {
        CorsConfiguration c = new CorsConfiguration();
        // ok: traust-java-cors-any-origin-with-credentials
        c.addAllowedOriginPattern("*");
        c.setAllowCredentials(false);
        return c;
    }

    void addCorsMappings(CorsRegistry registry) {
        // ruleid: traust-java-cors-any-origin-with-credentials
        registry.addMapping("/**").allowedOriginPatterns("*").allowCredentials(true);
    }

    void echo(HttpServletRequest req, HttpServletResponse resp) {
        // ruleid: traust-java-cors-any-origin-with-credentials
        resp.setHeader("Access-Control-Allow-Origin", req.getHeader("Origin"));
        resp.setHeader("Access-Control-Allow-Credentials", "true");
    }
}
