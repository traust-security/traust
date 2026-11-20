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

    SecurityFilterChain legacyOpen(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.requestMatcher(EndpointRequest.toAnyEndpoint()).authorizeRequests().anyRequest().permitAll();
        return http.build();
    }

    SecurityFilterChain legacyProtected(HttpSecurity http) throws Exception {
        // Matching the same endpoints is safe when authorization requires an operator.
        // ok: traust-java-data-exposure-actuator-permit-all
        http.requestMatcher(EndpointRequest.toAnyEndpoint()).authorizeRequests().anyRequest().hasRole("OPS");
        return http.build();
    }

    SecurityFilterChain legacyWildcard(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.requestMatcher(EndpointRequest.toAnyEndpoint()).authorizeRequests().antMatchers("/**").permitAll();
        return http.build();
    }

    SecurityFilterChain modernChained(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests().anyRequest().permitAll();
        return http.build();
    }

    SecurityFilterChain modernWildcard(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeRequests().antMatchers("/**").permitAll();
        return http.build();
    }

    SecurityFilterChain requestMatcherModernAuthorization(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.requestMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests().anyRequest().permitAll();
        return http.build();
    }

    SecurityFilterChain requestMatcherLambda(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.requestMatcher(EndpointRequest.toAnyEndpoint()).authorizeRequests(a -> a.anyRequest().permitAll());
        return http.build();
    }

    SecurityFilterChain securityMatcherLambda(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests(a -> a.anyRequest().permitAll());
        return http.build();
    }

    SecurityFilterChain legacyLambdaWildcard(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.requestMatcher(EndpointRequest.toAnyEndpoint()).authorizeRequests(a -> a.antMatchers("/**").permitAll());
        return http.build();
    }

    SecurityFilterChain securityMatcherLambdaWildcard(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeRequests(a -> a.antMatchers("/**").permitAll());
        return http.build();
    }

    SecurityFilterChain blockLambda(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests(a -> {
            a.anyRequest().permitAll();
        });
        return http.build();
    }

    SecurityFilterChain blockLambdaWildcard(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.requestMatcher(EndpointRequest.toAnyEndpoint()).authorizeRequests(a -> {
            a.antMatchers("/**").permitAll();
        });
        return http.build();
    }

    SecurityFilterChain selectionOnly(HttpSecurity http) throws Exception {
        // ok: traust-java-data-exposure-actuator-permit-all
        http.requestMatcher(EndpointRequest.toAnyEndpoint());
        // ok: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint());
        return http.build();
    }

    SecurityFilterChain modernProtected(HttpSecurity http) throws Exception {
        // ok: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests().anyRequest().authenticated();
        // ok: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeRequests().antMatchers("/**").hasRole("OPS");
        return http.build();
    }

    SecurityFilterChain protectedLambdas(HttpSecurity http) throws Exception {
        // ok: traust-java-data-exposure-actuator-permit-all
        http.requestMatcher(EndpointRequest.toAnyEndpoint()).authorizeRequests(a -> a.anyRequest().authenticated());
        // ok: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests(a -> a.anyRequest().hasRole("OPS"));
        // ok: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeRequests(a -> {
            a.antMatchers("/**").hasRole("OPS");
        });
        return http.build();
    }

    SecurityFilterChain protectedActuatorWithOpenFallback(HttpSecurity http) throws Exception {
        // The anonymous fallback must not override the earlier actuator branch.
        // ok: traust-java-data-exposure-actuator-permit-all
        http.requestMatcher(EndpointRequest.toAnyEndpoint()).authorizeRequests()
            .requestMatchers(EndpointRequest.toAnyEndpoint()).hasRole("OPS")
            .anyRequest().permitAll();
        // ok: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests(a -> a
            .requestMatchers(EndpointRequest.toAnyEndpoint()).authenticated()
            .anyRequest().permitAll());
        // ok: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests(a -> {
            a.requestMatchers(EndpointRequest.toAnyEndpoint()).hasRole("OPS");
            a.anyRequest().permitAll();
        });
        return http.build();
    }

    SecurityFilterChain healthOnly(HttpSecurity http) throws Exception {
        // ok: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.to("health", "info")).authorizeHttpRequests(a -> a.anyRequest().permitAll());
        return http.build();
    }

    SecurityFilterChain narrowAnonymousMatcher(HttpSecurity http) throws Exception {
        // A literal health matcher is not the wildcard authorization variant.
        // ok: traust-java-data-exposure-actuator-permit-all
        http.requestMatcher(EndpointRequest.toAnyEndpoint()).authorizeRequests().antMatchers("/actuator/health").permitAll();
        return http.build();
    }

    SecurityFilterChain unrelatedOpenChain(HttpSecurity actuator, HttpSecurity app) throws Exception {
        // ok: traust-java-data-exposure-actuator-permit-all
        actuator.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests(a -> a.anyRequest().hasRole("OPS"));
        // ok: traust-java-data-exposure-actuator-permit-all
        app.authorizeHttpRequests(a -> a.anyRequest().permitAll());
        return actuator.build();
    }

    SecurityFilterChain narrowProtectionChained(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.requestMatcher(EndpointRequest.toAnyEndpoint()).authorizeRequests()
            .antMatchers("/actuator/health").hasRole("OPS")
            .anyRequest().permitAll();
        return http.build();
    }

    SecurityFilterChain narrowProtectionLambda(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests(a -> a
            .requestMatchers("/actuator/health").authenticated()
            .anyRequest().permitAll());
        return http.build();
    }

    SecurityFilterChain narrowProtectionBlock(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests(a -> {
            a.requestMatchers("/actuator/health").hasRole("OPS");
            a.anyRequest().permitAll();
        });
        return http.build();
    }

    SecurityFilterChain multipleNarrowProtectionChained(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeRequests()
            .antMatchers("/actuator/health").hasRole("OPS")
            .antMatchers("/actuator/info").authenticated()
            .anyRequest().permitAll();
        return http.build();
    }

    SecurityFilterChain multipleNarrowProtectionLambda(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests(a -> a
            .requestMatchers("/actuator/health").hasRole("OPS")
            .requestMatchers("/actuator/info").authenticated()
            .anyRequest().permitAll());
        return http.build();
    }

    SecurityFilterChain multipleNarrowProtectionBlock(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests(a -> {
            a.requestMatchers("/actuator/health").hasRole("OPS");
            a.requestMatchers("/actuator/info").authenticated();
            a.anyRequest().permitAll();
        });
        return http.build();
    }

    SecurityFilterChain wholeProtectionBeforeNarrowChained(HttpSecurity http) throws Exception {
        // ok: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeRequests()
            .requestMatchers(EndpointRequest.toAnyEndpoint()).hasRole("OPS")
            .antMatchers("/actuator/health").authenticated()
            .anyRequest().permitAll();
        return http.build();
    }

    SecurityFilterChain wholeProtectionBeforeNarrowLambda(HttpSecurity http) throws Exception {
        // ok: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests(a -> a
            .requestMatchers(EndpointRequest.toAnyEndpoint()).hasRole("OPS")
            .requestMatchers("/actuator/health").authenticated()
            .anyRequest().permitAll());
        return http.build();
    }

    SecurityFilterChain wholeProtectionBeforeNarrowBlock(HttpSecurity http) throws Exception {
        // ok: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests(a -> {
            a.requestMatchers(EndpointRequest.toAnyEndpoint()).hasRole("OPS");
            a.requestMatchers("/actuator/health").authenticated();
            a.anyRequest().permitAll();
        });
        return http.build();
    }

    SecurityFilterChain literalBasePathAndUniversalProtection(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeRequests()
            .antMatchers("/actuator/**").hasRole("OPS")
            .anyRequest().permitAll();
        // ok: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests(a -> {
            a.requestMatchers("/**").authenticated();
            a.anyRequest().permitAll();
        });
        return http.build();
    }

    SecurityFilterChain earlierAnonymousWildcard(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeRequests()
            .antMatchers("/**").permitAll()
            .anyRequest().permitAll();
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests(a -> a
            .requestMatchers("/**").permitAll()
            .anyRequest().permitAll());
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests(a -> {
            a.requestMatchers("/**").permitAll();
            a.anyRequest().permitAll();
        });
        return http.build();
    }

    SecurityFilterChain unrelatedProtectionInsideLambda(
        HttpSecurity http,
        AuthorizationManagerRequestMatcherRegistry other
    ) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests(a -> {
            other.requestMatchers(EndpointRequest.toAnyEndpoint()).authenticated();
            a.requestMatchers("/actuator/health").hasRole("OPS");
            a.anyRequest().permitAll();
        });
        return http.build();
    }

    SecurityFilterChain wholeProtectionWithinEarlierBlockChain(HttpSecurity http) throws Exception {
        // ok: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests(a -> {
            a.requestMatchers("/actuator/health").hasRole("OPS")
                .requestMatchers(EndpointRequest.toAnyEndpoint()).authenticated();
            a.anyRequest().permitAll();
        });
        return http.build();
    }
}

@org.springframework.test.context.TestPropertySource(
    properties = "management.endpoints.web.base-path=/manage"
)
class CustomManagementPaths {
    SecurityFilterChain defaultPathGuardChained(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeRequests()
            .antMatchers("/actuator/**").hasRole("OPS")
            .anyRequest().permitAll();
        return http.build();
    }

    SecurityFilterChain defaultPathGuardLambda(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests(a -> a
            .requestMatchers("/actuator/**").authenticated()
            .anyRequest().permitAll());
        return http.build();
    }

    SecurityFilterChain defaultPathGuardBlock(HttpSecurity http) throws Exception {
        // ruleid: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests(a -> {
            a.mvcMatchers("/actuator/**").hasRole("OPS");
            a.anyRequest().permitAll();
        });
        return http.build();
    }

    SecurityFilterChain endpointAwareGuard(HttpSecurity http) throws Exception {
        // ok: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests(a -> a
            .requestMatchers(EndpointRequest.toAnyEndpoint()).hasRole("OPS")
            .anyRequest().permitAll());
        return http.build();
    }

    SecurityFilterChain universalGuard(HttpSecurity http) throws Exception {
        // ok: traust-java-data-exposure-actuator-permit-all
        http.securityMatcher(EndpointRequest.toAnyEndpoint()).authorizeHttpRequests(a -> {
            a.requestMatchers("/**").authenticated();
            a.anyRequest().permitAll();
        });
        return http.build();
    }
}
