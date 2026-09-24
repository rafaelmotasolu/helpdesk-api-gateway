package com.solutis.projeto.helpdesk_api_gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.ArrayList;
import java.util.List;

@Configuration
public class CorsConfig {

    @Bean
    public CorsWebFilter corsWebFilter(
            @Value("${cors.allowed-origins:http://localhost:3000,http://localhost:5173,http://localhost:80,http://localhost,http://127.0.0.1:3000,http://127.0.0.1:5173,http://127.0.0.1:80,http://localhost:*,http://127.0.0.1:*}")
            String allowedOrigins) {
        CorsConfiguration corsConfig = new CorsConfiguration();

        List<String> origins = new ArrayList<>();
        if (allowedOrigins != null) {
            for (String origin : allowedOrigins.split(",")) {
                String trimmed = origin.trim();
                if (!trimmed.isEmpty()) {
                    origins.add(trimmed);
                }
            }
        }

        corsConfig.setAllowedOriginPatterns(origins.isEmpty() ? List.of("*") : origins);
        corsConfig.setMaxAge(3600L);
        corsConfig.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        corsConfig.setAllowedHeaders(List.of("*"));
        corsConfig.setExposedHeaders(List.of("Authorization", "Content-Type", "X-User-Id", "X-User-Role", "X-User-Email"));
        corsConfig.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);

        return new CorsWebFilter(source);
    }
}