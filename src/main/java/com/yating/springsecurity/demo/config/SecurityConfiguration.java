package com.yating.springsecurity.demo.config;

import com.yating.springsecurity.demo.Provider.CustomFormLoginAuthenticationProvider;
import com.yating.springsecurity.demo.enumeration.TokenType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
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
    private  CustomFormLoginAuthenticationProvider customFormLoginAuthenticationProvider;

    @Autowired
    private LdapAuthenticationProvider ldapAuthenticationProvider;

    @Autowired
    private CustomKeycloakLogoutHandler customKeycloakLogoutHandler;

    @Autowired
    private ValidateTokenFilter validateTokenFilter;

    @Bean
    SecurityFilterChain clientSecurityFilterChain(HttpSecurity http) throws Exception {

        http.csrf().disable();
        http.cors().disable();

        http.sessionManagement(sessionManagement -> sessionManagement
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));  // Allows sessions when needed

        http.addFilterBefore(validateTokenFilter, BearerTokenAuthenticationFilter.class);

        http
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers(   "/login").permitAll()  // 允許訪問首頁
                        .anyRequest().authenticated()      // 其他請求需要認證
                )
                .formLogin(formLogin -> formLogin
                        .successHandler(new CustomAuthenticationSuccessHandler()) // 設置自定義成功處理器
                        .permitAll());

        http .saml2Login(saml2 -> saml2
                .successHandler(new CustomSaml2LoginSuccessHandler())
        ).saml2Metadata(Customizer.withDefaults())
                .saml2Logout(Customizer.withDefaults());

        http.oauth2Login(oauth2Login ->
                oauth2Login.successHandler(customOAuth2LoginSuccessHandler));
        http.oauth2Client(Customizer.withDefaults()).oauth2ResourceServer(
                oauth2 -> oauth2.opaqueToken(Customizer.withDefaults()).bearerTokenResolver(bearerTokenResolver())
        );
        http.authenticationManager(authenticationManager(http));

        http.logout()
                .addLogoutHandler(customKeycloakLogoutHandler)
                .deleteCookies(TokenType.ACCESS_TOKEN.getTokenName(),TokenType.REFRESH_TOKEN.getTokenName())
                .invalidateHttpSession(true)
                .permitAll();

        return http.build();
    }

    @Bean
    public BearerTokenResolver bearerTokenResolver() {
        return new CookieBearerTokenResolver();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);

        authenticationManagerBuilder.authenticationProvider(customFormLoginAuthenticationProvider);

        authenticationManagerBuilder.authenticationProvider(ldapAuthenticationProvider);

        return authenticationManagerBuilder.build();
    }

}
