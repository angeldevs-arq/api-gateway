package com.angeldevs.api_gateway;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Order(1)
public class AuthenticationFilter implements GlobalFilter {

    @Autowired
    private JwtTokenValidator jwtTokenValidator;

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    // Endpoints públicos
    private static final String[] PUBLIC_ENDPOINTS = {
            "/api/v1/iam/sign-in",
            "/api/v1/iam/sign-up"
    };

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, org.springframework.cloud.gateway.filter.GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // Si es endpoint público → continuar sin validar
        for (String publicPath : PUBLIC_ENDPOINTS) {
            if (path.startsWith(publicPath)) {
                return chain.filter(exchange);
            }
        }

        // Obtener token del header Authorization
        String authHeader = exchange.getRequest().getHeaders().getFirst(AUTHORIZATION_HEADER);
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return this.unauthorized(exchange, "Missing or invalid Authorization header");
        }

        String token = authHeader.substring(BEARER_PREFIX.length());

        // Validar token
        if (!jwtTokenValidator.validateToken(token)) {
            return this.unauthorized(exchange, "Invalid or expired token");
        }

        // Si el token es válido, continuar con el flujo
        return chain.filter(exchange);
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }
}

