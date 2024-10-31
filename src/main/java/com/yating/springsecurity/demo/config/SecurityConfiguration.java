package com.yating.springsecurity.demo.config;

import com.yating.springsecurity.demo.enumeration.TokenType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfiguration {
    @Autowired
    private CustomOAuth2LoginSuccessHandler customOAuth2LoginSuccessHandler;

    @Autowired
    private CustomKeycloakLogoutHandler customKeycloakLogoutHandler;

    @Autowired
    private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    @Autowired
    private ValidateTokenFilter validateTokenFilter;

    @Bean
    SecurityFilterChain clientSecurityFilterChain(HttpSecurity http) throws Exception {


        http.csrf().disable();
        http.cors().disable();

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.addFilterBefore(validateTokenFilter, BearerTokenAuthenticationFilter.class);

        http.authorizeHttpRequests(requests -> {
                    requests.requestMatchers("/").permitAll()
                            .anyRequest().authenticated();
                }).formLogin(Customizer.withDefaults());

        http.oauth2Login(oauth2Login ->
                oauth2Login.successHandler(customOAuth2LoginSuccessHandler));


        http.oauth2Client(Customizer.withDefaults()).oauth2ResourceServer(
                oauth2 -> oauth2.opaqueToken(Customizer.withDefaults()).bearerTokenResolver(bearerTokenResolver())
        );

        http.logout().addLogoutHandler(customKeycloakLogoutHandler)
                .deleteCookies(TokenType.ACCESS_TOKEN.getTokenName(),TokenType.REFRESH_TOKEN.getTokenName())
                .invalidateHttpSession(true)
                .permitAll();
        http.exceptionHandling(httpSecurityExceptionHandlingConfigurer -> httpSecurityExceptionHandlingConfigurer.authenticationEntryPoint(customAuthenticationEntryPoint));
        return http.build();
    }

    @Bean
    public BearerTokenResolver bearerTokenResolver() {
        return new CookieBearerTokenResolver();
    }

}
