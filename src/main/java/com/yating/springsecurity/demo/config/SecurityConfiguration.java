package com.yating.springsecurity.demo.config;

import com.yating.springsecurity.demo.enumeration.TokenType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
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

        http
                .sessionManagement(sessionManagement -> sessionManagement
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));  // Allows sessions when needed


    //only for keycloaklogin
        http.addFilterBefore(validateTokenFilter, BearerTokenAuthenticationFilter.class);



//
//        http.authorizeHttpRequests(requests -> {
//                    requests.requestMatchers("/").permitAll()
//                            .anyRequest().authenticated();
//                }).formLogin(Customizer.withDefaults());

        http
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers(   "/login").permitAll()  // 允許訪問首頁
                        .anyRequest().authenticated()      // 其他請求需要認證
                )
                .formLogin(formLogin -> formLogin
                        .defaultSuccessUrl("/demo/test", true) // Redirects to this URL on successful login
                        .permitAll());                      // Allows all users to access the login page
//                .formLogin(Customizer.withDefaults()                  // 允許所有人訪問登入頁面
//                ).formLogin(formLogin  -> formLogin.defaultSuccessUrl("/demo/test", true)
//                        .permitAll()););


        http.oauth2Login(oauth2Login ->
                oauth2Login.successHandler(customOAuth2LoginSuccessHandler));


        http.oauth2Client(Customizer.withDefaults()).oauth2ResourceServer(
                oauth2 -> oauth2.opaqueToken(Customizer.withDefaults()).bearerTokenResolver(bearerTokenResolver())
        );

        http.logout().addLogoutHandler(customKeycloakLogoutHandler)
                .deleteCookies(TokenType.ACCESS_TOKEN.getTokenName(),TokenType.REFRESH_TOKEN.getTokenName())
                .invalidateHttpSession(true)
                .permitAll();
//        http.exceptionHandling(httpSecurityExceptionHandlingConfigurer -> httpSecurityExceptionHandlingConfigurer.authenticationEntryPoint(customAuthenticationEntryPoint));
        return http.build();
    }

    @Bean
    public BearerTokenResolver bearerTokenResolver() {
        return new CookieBearerTokenResolver();
    }

    @Bean
    public BCryptPasswordEncoder bcryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /***
     *formlogin 配置user&password
     *
     */
    @Bean
    public InMemoryUserDetailsManager userDetailsService(BCryptPasswordEncoder bCryptPasswordEncoder) {

        UserDetails userDetails = User.builder()
                .username("user")
                .password(bCryptPasswordEncoder.encode("user"))
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }
    /**
     * DaoAuthenticationProvider is an AuthenticationProvider implementation that uses a UserDetailsService and PasswordEncoder to authenticate a username and password.
     *https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/dao-authentication-provider.html
     */
    @Bean
    public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(new BCryptPasswordEncoder());
        return authProvider;
    }

}
