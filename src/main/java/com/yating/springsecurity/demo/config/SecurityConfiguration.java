package com.yating.springsecurity.demo.config;


import com.yating.springsecurity.demo.Provider.CustomFormLoginAuthenticationProvider;
import com.yating.springsecurity.demo.Provider.LdapProviderConfig;
import com.yating.springsecurity.demo.enumeration.TokenType;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.security.x509.X509Support;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.LdapAuthenticator;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;

import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml4LogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestResolver;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

import java.io.File;
import java.io.IOException;
import java.security.cert.X509Certificate;

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
    private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private ValidateTokenFilter validateTokenFilter;

    @Value("classpath:keycloak.crt")
    File verificationKey;
    @Bean
    SecurityFilterChain clientSecurityFilterChain(HttpSecurity http) throws Exception {

        http.csrf().disable();
        http.cors().disable();

        http.sessionManagement(sessionManagement -> sessionManagement
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
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);

        // 註冊自定義的表單登錄認證提供者
        authenticationManagerBuilder.authenticationProvider(customFormLoginAuthenticationProvider);

//        // 註冊 LDAP 認證提供者
        authenticationManagerBuilder.authenticationProvider(ldapAuthenticationProvider);

        return authenticationManagerBuilder.build();
    }


//    @Bean
//    public AuthenticationManager authManager(HttpSecurity http,
//                                             CustomFormLoginAuthenticationProvider customFormLoginAuthenticationProvider,
//                                             LdapAuthenticationProvider ldapAuthenticationProvider) throws Exception {
//        AuthenticationManagerBuilder authenticationManagerBuilder =
//                http.getSharedObject(AuthenticationManagerBuilder.class);
//
//        // 註冊自定義的表單登錄認證提供者
//        authenticationManagerBuilder.authenticationProvider(customFormLoginAuthenticationProvider);
//
//        // 註冊 LDAP 認證提供者
//        authenticationManagerBuilder.authenticationProvider(ldapAuthenticationProvider);
//
//        return authenticationManagerBuilder.build();
//    }

//


//    @Bean
//    public RelyingPartyRegistrationRepository relyingPartyRegistrations() throws Exception {
//        // 解码并加载 Keycloak 的公钥证书
//        X509Certificate certificate = X509Support.decodeCertificate(this.verificationKey);
//        Saml2X509Credential credential = Saml2X509Credential.verification(certificate);
//
//        // 配置 SAML 客户端（服务提供者）
//        RelyingPartyRegistration registration = RelyingPartyRegistration
//                .withRegistrationId("saml-test")  // 这里的 ID 是服务提供者的 ID，您可以自定义
//                .entityId("saml-test")
//                .assertingPartyDetails(party -> party
//                        .entityId("http://localhost:8080/realms/test-oauth") // 这里是服务提供者（SP）的 entityId
//                        .singleSignOnServiceLocation("http://localhost:8080/realms/test-oauth/protocol/saml")  // Keycloak 中的 SSO 端点
//                        .wantAuthnRequestsSigned(false)  // 是否需要认证请求签名
//                        .verificationX509Credentials(c -> c.add(credential))  // 使用 Keycloak 的公钥证书来验证 SAML 响应
//                )
//                .build();
//
//
//        // 返回内存中保存的 RelyingPartyRegistration
//        return new InMemoryRelyingPartyRegistrationRepository(registration);
//    }



}
