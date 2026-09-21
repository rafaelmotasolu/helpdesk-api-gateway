package com.solutis.projeto.helpdesk_api_gateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.impl.DefaultClaims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationFilterTest {

    @Mock
    private JwtUtils jwtUtils;

    @Mock
    private GatewayFilterChain chain;

    private AuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        filter = new AuthenticationFilter(jwtUtils);
    }

    @Test
    @DisplayName("Deve permitir requisições para rotas públicas sem validar Authorization header")
    void shouldAllowPublicEndpoints() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/users/auth/login").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(chain.filter(any(ServerWebExchange.class))).thenReturn(Mono.empty());

        Mono<Void> result = filter.filter(exchange, chain);
        result.block();

        verify(chain).filter(exchange);
        verifyNoInteractions(jwtUtils);
    }

    @Test
    @DisplayName("Deve retornar 401 quando Authorization header estiver ausente em rota protegida")
    void shouldReturn401WhenAuthorizationHeaderMissing() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/tickets").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        Mono<Void> result = filter.filter(exchange, chain);
        result.block();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        verifyNoInteractions(chain);
    }

    @Test
    @DisplayName("Deve retornar 401 quando Authorization header não iniciar com Bearer")
    void shouldReturn401WhenAuthorizationHeaderNotBearer() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/tickets")
                .header(HttpHeaders.AUTHORIZATION, "Basic 123456")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        Mono<Void> result = filter.filter(exchange, chain);
        result.block();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        verifyNoInteractions(chain);
    }

    @Test
    @DisplayName("Deve retornar 401 quando token JWT for inválido")
    void shouldReturn401WhenTokenIsInvalid() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/tickets")
                .header(HttpHeaders.AUTHORIZATION, "Bearer invalid_token")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(jwtUtils.isInvalid("invalid_token")).thenReturn(true);

        Mono<Void> result = filter.filter(exchange, chain);
        result.block();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        verifyNoInteractions(chain);
    }

    @Test
    @DisplayName("Deve injetar cabeçalhos X-User-* e prosseguir na cadeia quando token for válido")
    void shouldInjectHeadersAndProceedWhenTokenIsValid() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/tickets")
                .header(HttpHeaders.AUTHORIZATION, "Bearer valid_token")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        Claims claims = new DefaultClaims(Map.of(
                Claims.SUBJECT, "42",
                "email", "user@empresa.com",
                "role", "ROLE_ADMIN"
        ));

        when(jwtUtils.isInvalid("valid_token")).thenReturn(false);
        when(jwtUtils.getClaims("valid_token")).thenReturn(claims);
        when(chain.filter(any(ServerWebExchange.class))).thenReturn(Mono.empty());

        Mono<Void> result = filter.filter(exchange, chain);
        result.block();

        ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(captor.capture());

        ServerWebExchange captured = captor.getValue();
        assertEquals("42", captured.getRequest().getHeaders().getFirst("X-User-Id"));
        assertEquals("user@empresa.com", captured.getRequest().getHeaders().getFirst("X-User-Email"));
        assertEquals("ROLE_ADMIN", captured.getRequest().getHeaders().getFirst("X-User-Role"));
    }
}

