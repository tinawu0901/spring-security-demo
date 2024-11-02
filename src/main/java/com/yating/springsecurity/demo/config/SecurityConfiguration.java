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
import org.springframework.security.crypto.password.PasswordEncoder;
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
    private CustomKeycloakLogoutHandler customKeycloakLogoutHandler;

    @Autowired
    private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    @Autowired
    private PasswordEncoder passwordEncoder;

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

        http
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers(   "/login").permitAll()  // 允許訪問首頁
                        .anyRequest().authenticated()      // 其他請求需要認證
                )
                .formLogin(formLogin -> formLogin
                        .successHandler(new CustomAuthenticationSuccessHandler()) // 設置自定義成功處理器
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



//
//    /***
//     *formlogin 配置user&password
//     *簡易的儲存帳密 若自定義User無法從UserDetails獲取到
//     * always retrun user
//     */
//    @Bean
//    public UserDetailsService  userDetailsService(BCryptPasswordEncoder bCryptPasswordEncoder) {
//        UserDetails userDetails = User.builder()
//                .username("user")
//                .password(bCryptPasswordEncoder.encode("user"))
//                .roles("USER")
//                .build();
//        return new InMemoryUserDetailsManager(userDetails);
//    }
//    /**
//     * DaoAuthenticationProvider is an AuthenticationProvider implementation that uses a UserDetailsService and PasswordEncoder to authenticate a username and password.
//     *https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/dao-authentication-provider.html
//     * 如果不行可以自己實作AuthenticationProvider來做自定義認證
//     */
//    @Bean
//    public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService) {
//        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
//        authProvider.setUserDetailsService(userDetailsService);
//        authProvider.setPasswordEncoder(new BCryptPasswordEncoder());
//        return authProvider;
//    }

    @Bean
    public AuthenticationManager authManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(customFormLoginAuthenticationProvider);
        return authenticationManagerBuilder.build();
    }


}
