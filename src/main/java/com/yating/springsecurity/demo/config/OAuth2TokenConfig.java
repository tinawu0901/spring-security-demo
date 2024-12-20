package com.yating.springsecurity.demo.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
import org.springframework.web.client.RestTemplate;
@Configuration
public class OAuth2TokenConfig {

    @Value("${spring.security.oauth2.resourceserver.test-oauth.introspection-uri}")
    private String introspectionUri;

    @Value("${spring.security.oauth2.resourceserver.test-oauth.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.resourceserver.test-oauth.client-secret}")
    private String clientSecret;

    @Bean
    public OpaqueTokenAuthenticationProvider opaqueTokenAuthenticationProvider() {
        return new OpaqueTokenAuthenticationProvider(opaqueTokenIntrospector());
    }
    @Bean
    public OAuth2AuthorizedClientProvider jwtBearer() {

        return new JwtBearerOAuth2AuthorizedClientProvider();
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }



    @Bean
    public OpaqueTokenIntrospector opaqueTokenIntrospector() {
        return new SpringOpaqueTokenIntrospector(introspectionUri, clientId, clientSecret);
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientService authorizedClientService) {


        OAuth2AuthorizedClientProvider authorizedClientProvider =
                OAuth2AuthorizedClientProviderBuilder.builder()
                        .authorizationCode()
                        .refreshToken()
                        .build();

        // Set up the authorized client manager with the provider
        AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager =
                new AuthorizedClientServiceOAuth2AuthorizedClientManager(
                        clientRegistrationRepository, authorizedClientService);

        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

        return authorizedClientManager;
    }

}
