/*
 * Copyright 2022 agwlvssainokuni
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cherry.apigateway.gatewayfilter;

import java.util.Arrays;
import java.util.List;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class AddRequestHeaderFromJwtGatewayFilterFactory
        extends AbstractGatewayFilterFactory<AddRequestHeaderFromJwtGatewayFilterFactory.Config> {

    public AddRequestHeaderFromJwtGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> ReactiveSecurityContextHolder.getContext()
                // JWTクレームを取得する。
                .map(SecurityContext::getAuthentication).map(Authentication::getPrincipal)
                .filter(Jwt.class::isInstance).map(Jwt.class::cast)
                .map(jwt -> jwt.getClaimAsString(config.getClaim()))
                // JWTクレームをリクエストヘッダへ設定する。
                .flatMap(claim -> Mono.just(exchange).map(ServerWebExchange::getRequest)
                        .map(ServerHttpRequest::mutate)
                        .map(req -> req.header(config.getHeader(), claim))
                        .map(ServerHttpRequest.Builder::build))
                // リクエストを更新する。
                .flatMap(req -> Mono.just(exchange)
                        .map(ServerWebExchange::mutate)
                        .map(exchg -> exchg.request(req))
                        .map(ServerWebExchange.Builder::build))
                // JWTクレームが存在しない場合はリクエストを更新しない。
                .switchIfEmpty(Mono.just(exchange))
                // フィルタ処理を進める。
                .flatMap(chain::filter);
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Arrays.asList("header", "claim");
    }

    public static class Config {

        private String header;
        private String claim;

        public String getHeader() {
            return header;
        }

        public void setHeader(String header) {
            this.header = header;
        }

        public String getClaim() {
            return claim;
        }

        public void setClaim(String claim) {
            this.claim = claim;
        }
    }

}
