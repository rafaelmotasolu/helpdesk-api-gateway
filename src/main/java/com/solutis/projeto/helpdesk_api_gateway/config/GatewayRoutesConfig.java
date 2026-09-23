package com.solutis.projeto.helpdesk_api_gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayRoutesConfig {

    @Bean
    public RouteLocator customRouteLocator(
            RouteLocatorBuilder builder,
            @Value("${USER_SERVICE_URL:http://localhost:8081}") String userServiceUrl,
            @Value("${TICKET_SERVICE_URL:http://localhost:8082}") String ticketServiceUrl,
            @Value("${NOTIFICATION_SERVICE_URL:http://localhost:8083}") String notificationServiceUrl) {

        return builder.routes()
                .route("user-service-auth", r -> r
                        .path("/api/auth/**")
                        .filters(f -> f.stripPrefix(1))
                        .uri(userServiceUrl))
                .route("user-service", r -> r
                        .path("/api/users/**")
                        .filters(f -> f.stripPrefix(1))
                        .uri(userServiceUrl))
                .route("ticket-service", r -> r
                        .path("/api/tickets/**")
                        .filters(f -> f.stripPrefix(1))
                        .uri(ticketServiceUrl))
                .route("notification-service", r -> r
                        .path("/api/notifications/**")
                        .filters(f -> f.stripPrefix(1))
                        .uri(notificationServiceUrl))
                .build();
    }
}

