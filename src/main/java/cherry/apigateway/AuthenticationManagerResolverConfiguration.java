/*
 * Copyright 2022,2024 agwlvssainokuni
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
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.web.server.ServerWebExchange;
import com.azure.spring.cloud.autoconfigure.implementation.aad.security.jose.RestOperationsResourceRetriever;
import com.azure.spring.cloud.autoconfigure.implementation.aad.security.jwt.AadIssuerJwsKeySelector;
import com.azure.spring.cloud.autoconfigure.implementation.aad.security.jwt.AadJwtIssuerValidator;
import com.azure.spring.cloud.autoconfigure.implementation.aad.security.jwt.AadTrustedIssuerRepository;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
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
         * インスタンスを、AadB2cResourceServerAutoConfiguration に倣って自分で形成する。
         */

        var trustedIssuerRepository = new AadTrustedIssuerRepository("dummy");
        for (var entry : issuerMap) {
            trustedIssuerRepository.addTrustedIssuer(entry.issuer());
            trustedIssuerRepository.addSpecialOidcIssuerLocationMap(
                entry.issuer(),
                entry.oidcIssuerLocation());
        }

        var restTemplateBuilder = new RestTemplateBuilder();
        var resourceRetriever = new RestOperationsResourceRetriever(restTemplateBuilder);
        var keySelector = new AadIssuerJwsKeySelector(restTemplateBuilder, trustedIssuerRepository, resourceRetriever);
        var jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWTClaimsSetAwareJWSKeySelector(keySelector);
        var jwtDecoder = new NimbusJwtDecoder(jwtProcessor);
        jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(List.of(
            new AadJwtIssuerValidator(trustedIssuerRepository),
            new JwtTimestampValidator())));

        var authenticationManager = new JwtReactiveAuthenticationManager(
            token -> Mono.just(token).map(jwtDecoder::decode));
        return exchange -> Mono.just(authenticationManager);
    }

    public static record IssuerEntry(
        String issuer,
        String oidcIssuerLocation //
    ) {
    }

}
