package com.yating.springsecurity.demo.Provider;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;

@Configuration
public class LdapProviderConfig {
    @Value("${spring.ldap.urls}")
    private String ldapUrl;
    @Value("${spring.ldap.base}")
    private String baseDn;
    @Value("${spring.ldap.username}")
    private String adminDn;
    @Value("${spring.ldap.password}")
    private String adminPassword;


    /**
     * 配置 LDAP 認證提供者。
     *
     * @return LdapAuthenticationProvider
     */
    @Bean
    public LdapAuthenticationProvider ldapAuthenticationProvider() {
        return new LdapAuthenticationProvider(ldapAuthenticator(), ldapAuthoritiesPopulator());
    }

    @Bean
    public LdapTemplate ldapTemplate() {
        return new LdapTemplate(ldapContextSource());
    }


    /**
     * 配置 LDAP 綁定認證器，用於通過不同的查詢模式認證用戶。
     *
     * @return LdapAuthenticator
     *
     *
     */
    @Bean
    public LdapAuthenticator ldapAuthenticator() {
        BindAuthenticator ldapAuthenticator = new BindAuthenticator(ldapContextSource());

        // 配置多個用戶 DN 模式，支持 PG 和 SA 節點
        String[] userDnPatterns = {
                "cn={0},cn=PG,ou=ITteam",  // PG 節點的用戶
                "cn={0},cn=SA,ou=ITteam"   // SA 節點的用戶
        };
        ldapAuthenticator.setUserDnPatterns(userDnPatterns);

        return ldapAuthenticator;
    }


    /**
     * 配置 LDAP 權限加載器，用於從指定的組中獲取用戶權限。
     *
     * @return LdapAuthoritiesPopulator
     */
    @Bean
    public LdapAuthoritiesPopulator ldapAuthoritiesPopulator() {
        return new DefaultLdapAuthoritiesPopulator(ldapContextSource(), "ou=ITteam");
    }

    /**
     * 配置 LDAP 上下文源，提供 LDAP 連接的基本信息。
     *
     * @return LdapContextSource
     */
    @Bean
    public LdapContextSource ldapContextSource() {
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl(ldapUrl);
        contextSource.setBase(baseDn); // 設定根節點
        contextSource.setUserDn(adminDn);
        contextSource.setPassword(adminPassword);
        return contextSource;
    }

}
