package com.example.ledger;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

class WebChains {
    @Bean
    SecurityFilterChain browser(HttpSecurity http) throws Exception {
        // ruleid: traust-java-csrf-disabled-with-session-login
        http
            .csrf(c -> c.disable())
            .authorizeHttpRequests(a -> a.anyRequest().authenticated())
            .formLogin(f -> f.loginPage("/signin"));
        return http.build();
    }

    @Bean
    SecurityFilterChain sso(HttpSecurity http) throws Exception {
        // ruleid: traust-java-csrf-disabled-with-session-login
        http.csrf(AbstractHttpConfigurer::disable);
        http.oauth2Login(o -> {});
        return http.build();
    }

    SecurityFilterChain legacy(HttpSecurity http) throws Exception {
        // ruleid: traust-java-csrf-disabled-with-session-login
        http.csrf().disable().authorizeRequests().anyRequest().authenticated().and().formLogin();
        return http.build();
    }

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        // ok: traust-java-csrf-disabled-with-session-login
        http
            .csrf(c -> c.disable())
            .oauth2ResourceServer(r -> r.jwt(j -> {}));
        return http.build();
    }

    @Bean
    SecurityFilterChain kept(HttpSecurity http) throws Exception {
        http.formLogin(f -> {});
        return http.build();
    }
}
