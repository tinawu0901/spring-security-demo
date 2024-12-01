package com.yating.springsecurity.demo.Provider;

import com.yating.springsecurity.demo.dto.CustomUser;
import com.yating.springsecurity.demo.enumeration.LoginMethod;
import com.yating.springsecurity.demo.service.UserDetailsServiceImpl;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.stereotype.Component;

@Component
public class CustomFormLoginAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsServiceImpl userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final LdapAuthenticationProvider ldapAuthenticationProvider;

    public CustomFormLoginAuthenticationProvider(UserDetailsServiceImpl userDetailsService,
                                                 PasswordEncoder passwordEncoder,
                                                 LdapAuthenticationProvider ldapAuthenticationProvider) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.ldapAuthenticationProvider = ldapAuthenticationProvider;
    }
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String rawPassword = authentication.getCredentials().toString();

        try {
            CustomUser user = (CustomUser) userDetailsService.loadUserByUsername(username);
            if (passwordEncoder.matches(rawPassword, user.getPassword())) {
                return new UsernamePasswordAuthenticationToken(user, rawPassword, user.getAuthorities());
            }
        } catch (UsernameNotFoundException ex) {
            try {
                Authentication ldapAuth = ldapAuthenticationProvider.authenticate(
                        new UsernamePasswordAuthenticationToken(username, rawPassword)
                );

                // 從 ldapAuth 提取用戶信息
                UserDetails ldapUserDetails = (UserDetails) ldapAuth.getPrincipal();

                // 構造 CustomUser 對象，提取必要的信息
                CustomUser customUser = new CustomUser(
                        ldapUserDetails.getUsername(),  // 從 LDAP 獲取用戶名
                        ldapUserDetails.getPassword(),  // 從 LDAP 獲取密碼
                        ldapUserDetails.getAuthorities(), // 從 LDAP 獲取權限
                        null,  // 初始化 TOTP 密鑰為 null
                        false , // 設置 useMFE 為 false
                        LoginMethod.LDAP
                );

                // 返回包含 CustomUser 的 UsernamePasswordAuthenticationToken
                return new UsernamePasswordAuthenticationToken(
                        customUser,                         // 包裝 CustomUser
                        rawPassword,                        // 傳遞原始密碼
                        customUser.getAuthorities()         // 傳遞權限
                );
            } catch (AuthenticationException ldapEx) {
                // 捕獲 LDAP 認證失敗的情況
                System.out.println("LDAP 認證失敗");
                throw new BadCredentialsException("Invalid username or password");
            }
        }

        // 如果兩種認證都失敗，拋出憑證錯誤
        throw new BadCredentialsException("Invalid username or password");
    }


    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
