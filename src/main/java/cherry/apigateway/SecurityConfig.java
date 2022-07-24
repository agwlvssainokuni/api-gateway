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

package cherry.apigateway;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

@EnableWebFluxSecurity
public class SecurityConfig {

	@Bean
	public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) throws Exception {

		http.oauth2ResourceServer(oauth2 -> {
			oauth2.jwt();
		});

		http.cors(cors -> {
			CorsConfiguration corsConfiguration = new CorsConfiguration();
			corsConfiguration.applyPermitDefaultValues();
			UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
			source.registerCorsConfiguration("/prvapi/**", corsConfiguration);
			source.registerCorsConfiguration("/pubapi/**", corsConfiguration);
			cors.configurationSource(source);
		});

		http.authorizeExchange(authz -> {
			authz.pathMatchers("/prvapi/**")
					.authenticated();
			authz.pathMatchers("/pubapi/**")
					.permitAll();
			authz.anyExchange().permitAll();
		});

		return http.build();
	}

}
