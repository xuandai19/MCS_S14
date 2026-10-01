package org.example.apigateway.jwt;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.example.apigateway.routes.RouterValidator;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final JwtUtils jwtUtils;
    private final RouterValidator routerValidator;
    private final ReactiveStringRedisTemplate redisTemplate;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        // Public paths → bỏ qua kiểm tra JWT
        if (!routerValidator.isSecured.test(request)) {
            return chain.filter(exchange);
        }

        // Lấy Authorization header (không dùng containsKey để tương thích Spring 7)
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return onError(exchange, HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7);

        try {
            if (!jwtUtils.validationToken(token)) {
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }

            Claims claims = jwtUtils.extractAllClaims(token);
            String jti = claims.get("jti", String.class);

            // Kiểm tra blacklist trên Redis (non-blocking)
            if (jti != null) {
                return redisTemplate.hasKey("blacklist:" + jti)
                        .flatMap(isBlacklisted -> {
                            if (Boolean.TRUE.equals(isBlacklisted)) {
                                return onError(exchange, HttpStatus.UNAUTHORIZED);
                            }
                            return continueFilter(exchange, chain, claims, token);
                        });
            }

            return continueFilter(exchange, chain, claims, token);
        } catch (Exception e) {
            return onError(exchange, HttpStatus.UNAUTHORIZED);
        }
    }

    private Mono<Void> continueFilter(ServerWebExchange exchange, GatewayFilterChain chain,
                                      Claims claims, String token) {
        try {
            Object userIdObj = claims.get("userId");
            String userIdStr = userIdObj != null ? String.valueOf(userIdObj) : "";
            Object rolesObj = claims.get("roles");
            String rolesStr = rolesObj != null ? rolesObj.toString() : "[]";

            ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                    .header("X-Auth-UserId", userIdStr)
                    .header("X-Auth-Roles", rolesStr)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .build();

            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        } catch (Exception e) {
            return onError(exchange, HttpStatus.UNAUTHORIZED);
        }
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        return response.setComplete();
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
