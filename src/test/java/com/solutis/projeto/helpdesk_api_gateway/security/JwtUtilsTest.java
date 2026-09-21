package com.solutis.projeto.helpdesk_api_gateway.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilsTest {

    private static final String SECRET = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
    private JwtUtils jwtUtils;

    @BeforeEach
    void setUp() {
        jwtUtils = new JwtUtils(SECRET);
    }

    @Test
    @DisplayName("Deve validar token JWT assinado corretamente e extrair claims")
    void shouldValidateCorrectJwtTokenAndExtractClaims() {
        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        String token = Jwts.builder()
                .subject("123")
                .claim("email", "usuario@teste.com")
                .claim("role", "ROLE_ADMIN")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(key)
                .compact();

        assertFalse(jwtUtils.isInvalid(token));

        var claims = jwtUtils.getClaims(token);
        assertEquals("123", claims.getSubject());
        assertEquals("usuario@teste.com", claims.get("email", String.class));
        assertEquals("ROLE_ADMIN", claims.get("role", String.class));
    }

    @Test
    @DisplayName("Deve invalidar token malformado ou expirado")
    void shouldInvalidateMalformedOrExpiredToken() {
        assertTrue(jwtUtils.isInvalid("token_invalido"));
        assertTrue(jwtUtils.isInvalid(""));
    }
}

