package com.example.ledger;

import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

class OpsChains {
    SecurityFilterChain open(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.authorizeHttpRequests(a -> a
            .requestMatchers(EndpointRequest.toAnyEndpoint()).permitAll()
            .anyRequest().authenticated());
        return http.build();
    }

    SecurityFilterChain byPath(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.authorizeHttpRequests(a -> a
            .requestMatchers("/actuator/**").permitAll());
        return http.build();
    }

    SecurityFilterChain scoped(HttpSecurity http) throws Exception {
        // ok: traust-java-data-exposure-actuator-permit-all
        http.authorizeHttpRequests(a -> a
            .requestMatchers(EndpointRequest.to("health", "info")).permitAll()
            .requestMatchers(EndpointRequest.toAnyEndpoint()).hasRole("OPS"));
        return http.build();
    }
}
