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

import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.web.server.ServerWebExchange;

import com.azure.spring.cloud.autoconfigure.aad.AadTrustedIssuerRepository;
import com.azure.spring.cloud.autoconfigure.aadb2c.AadB2cResourceServerAutoConfiguration;
import com.azure.spring.cloud.autoconfigure.aadb2c.properties.AadB2cProperties;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.proc.JWTClaimsSetAwareJWSKeySelector;
import com.nimbusds.jwt.proc.JWTProcessor;

import reactor.core.publisher.Mono;

@Configuration
@ConfigurationProperties(prefix = "cherry.api-gateway")
public class AuthenticationManagerResolverConfiguration {

	private List<String> issuerList;

	private List<IssuerEntry> issuerMap;

	public void setIssuerList(List<String> issuerList) {
		this.issuerList = issuerList;
	}

	public void setIssuerMap(List<IssuerEntry> issuerMap) {
		this.issuerMap = issuerMap;
	}

	@Bean
	@ConditionalOnProperty(name = "cherry.api-gateway.resolver-type", havingValue = "multitenant")
	public ReactiveAuthenticationManagerResolver<ServerWebExchange> multitenantAuthenticationManagerResolver() {
		return new JwtIssuerReactiveAuthenticationManagerResolver(issuerList);
	}

	@Bean
	@ConditionalOnProperty(name = "cherry.api-gateway.resolver-type", havingValue = "aadb2c")
	public ReactiveAuthenticationManagerResolver<ServerWebExchange> aadb2cAuthenticationManagerResolver() {

		/*
		 * Reactive のときは AadB2cResourceServerAutoConfiguration が構成されない。
		 * そのため AD B2C 向けの ReactiveAuthenticationManagerResolver に必要な
		 * インスタンスを、AadB2cResourceServerAutoConfiguration を自分で呼び出して
		 * 形成する。
		 */
		AadB2cResourceServerAutoConfiguration cfg = new AadB2cResourceServerAutoConfiguration(new AadB2cProperties(), new RestTemplateBuilder());

		AadTrustedIssuerRepository trustedIssuerRepository = new AadTrustedIssuerRepository("dummy");
		for (IssuerEntry entry : issuerMap) {
			trustedIssuerRepository.addTrustedIssuer(entry.getIssuer());
			trustedIssuerRepository.addSpecialOidcIssuerLocationMap(entry.getIssuer(), entry.getOidcIssuerLocation());
		}

		ResourceRetriever resourceRetriever = cfg.jwtResourceRetriever();
		JWTClaimsSetAwareJWSKeySelector<SecurityContext> keySelector = cfg
				.aadIssuerJwsKeySelector(trustedIssuerRepository, resourceRetriever);
		JWTProcessor<SecurityContext> jwtProcessor = cfg.jwtProcessor(keySelector);
		JwtDecoder jwtDecoder = cfg.jwtDecoder(jwtProcessor, trustedIssuerRepository);

		var authenticationManager = new JwtReactiveAuthenticationManager(
				token -> Mono.just(token).map(jwtDecoder::decode));
		return exchange -> Mono.just(authenticationManager);
	}

	public static class IssuerEntry {
		private String issuer;
		private String oidcIssuerLocation;

		public String getIssuer() {
			return issuer;
		}

		public void setIssuer(String issuer) {
			this.issuer = issuer;
		}

		public String getOidcIssuerLocation() {
			return oidcIssuerLocation;
		}

		public void setOidcIssuerLocation(String oidcIssuerLocation) {
			this.oidcIssuerLocation = oidcIssuerLocation;
		}
	}

}
