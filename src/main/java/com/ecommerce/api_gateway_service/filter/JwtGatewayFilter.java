package com.ecommerce.api_gateway_service.filter;



import com.ecommerce.api_gateway_service.security.JwtService;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class JwtGatewayFilter implements GlobalFilter {


    private final  JwtService jwtService;

    public JwtGatewayFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange,
                             GatewayFilterChain chain) {

        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().toString();


        if (path.startsWith("/auth/")) {
            return chain.filter(exchange);  // Mono<Void> not void
        }

        String authHeader = request.getHeaders()
                                   .getFirst("Authorization");



        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse()
                    .setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete(); // Mono<Void>
        }


        String token = authHeader.substring(7);

        String role = jwtService.extractRole(token);



        if (path.startsWith("/admin/")
                && !role.equals("ADMIN")) {

            exchange.getResponse()
                    .setStatusCode(HttpStatus.FORBIDDEN);

            return exchange.getResponse().setComplete();
        }

        if (path.startsWith("/products")
                && (request.getMethod().name().equals("POST")
                || request.getMethod().name().equals("PUT")
                || request.getMethod().name().equals("DELETE"))
                && !role.equals("BUSINESS")) {

            exchange.getResponse()
                    .setStatusCode(HttpStatus.FORBIDDEN);

            return exchange.getResponse().setComplete();
        }

        if (!jwtService.isValid(token)) {
            exchange.getResponse()
                    .setStatusCode(HttpStatus.UNAUTHORIZED);

            return exchange.getResponse().setComplete();
        }

        Long userId = jwtService.extractId(token);

        ServerHttpRequest mutatedRequest =
                request.mutate()
                        .header(
                                "X-User-Id",
                                String.valueOf(userId)
                        )
                        .build();

        ServerWebExchange mutatedExchange =
                exchange.mutate()
                        .request(mutatedRequest)
                        .build();

        // validate token, forward request
        return chain.filter(mutatedExchange);
    }
}