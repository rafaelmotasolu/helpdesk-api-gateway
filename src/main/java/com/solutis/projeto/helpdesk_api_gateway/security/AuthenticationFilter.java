package com.solutis.projeto.helpdesk_api_gateway.security;

import io.jsonwebtoken.Claims;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class AuthenticationFilter implements GlobalFilter, Ordered {

    private final JwtUtils jwtUtils;

    // Rotas públicas que não exigem validação de Bearer Token
    private final List<String> openApiEndpoints = List.of(
            "/api/users/auth/login",
            "/v3/api-docs",
            "/swagger-ui",
            "/actuator/health"
    );

    public AuthenticationFilter(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // 1. Se a rota for pública, segue adiante sem validar token
        if (isOpenEndpoint(path)) {
            return chain.filter(exchange);
        }

        // 2. Se não possuir header de autorização ou for inválido, barra com 401 Unauthorized
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return onError(exchange, HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7);

        // 3. Valida assinatura e expiração do token
        if (jwtUtils.isInvalid(token)) {
            return onError(exchange, HttpStatus.UNAUTHORIZED);
        }

        // 4. Extrai claims e injeta nos headers repassados para a rede interna
        Claims claims = jwtUtils.getClaims(token);
        ServerHttpRequest mutatedRequest = request.mutate()
                .header("X-User-Id", String.valueOf(claims.getSubject()))
                .header("X-User-Email", claims.get("email", String.class))
                .header("X-User-Role", claims.get("role", String.class))
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    private boolean isOpenEndpoint(String path) {
        return openApiEndpoints.stream().anyMatch(path::contains);
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        return response.setComplete();
    }

    @Override
    public int getOrder() {
        return -1; // Alta prioridade de execução na cadeia de filtros
    }
}
