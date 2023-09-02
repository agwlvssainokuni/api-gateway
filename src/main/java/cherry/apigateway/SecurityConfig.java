/*
 * Copyright 2022,2023 agwlvssainokuni
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

package cherry.apigateway;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.ServerWebExchange;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

	@Bean
	public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http,
			@Autowired(required = false) ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver)
			throws Exception {

		http.oauth2ResourceServer(oauth2 -> {
			if (resolver == null) {
				oauth2.jwt(jwtSpec -> {
				});
			} else {
				oauth2.authenticationManagerResolver(resolver);
			}
		});

		http.authorizeExchange(authz -> {

			// CORSはSpring Cloud Gatewayのglobalcors設定で処理することとする。
			// そのためにSpring SecurityがOPTIONSメソッドをスルーするよう構成する。
			// (前段のSpring Securityはアクセス許可し、後段のSpring Cloud Gateway
			// で処理する)
			// Spring SecurityはSpring Cloud Gatewayよりも前段階で実行されるため
			// この構成がないと「Spring Cloud Gatewayへ到達する前にSpring Security
			// によりアクセス拒否される」ことがありうる。
			authz.pathMatchers(HttpMethod.OPTIONS).permitAll();

			authz.pathMatchers("/prvapi/**")
					.authenticated();
			authz.pathMatchers("/pubapi/**")
					.permitAll();
			authz.anyExchange().permitAll();
		});

		return http.build();
	}

}
