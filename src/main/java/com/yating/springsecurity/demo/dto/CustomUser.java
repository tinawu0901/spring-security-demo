package com.yating.springsecurity.demo.dto;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
 // 此注解將生成所有的 getter 和 setter 方法
public class CustomUser implements UserDetails {
    private String username;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;
    private String totpSecret; // 用于存储 TOTP 密钥
    private boolean useMFE; // 表示用户是否需要使用 MFE

     public void setUsername(String username) {
         this.username = username;
     }

     public void setPassword(String password) {
         this.password = password;
     }

     public void setTotpSecret(String totpSecret) {
         this.totpSecret = totpSecret;
     }

     public void setUseMFE(boolean useMFE) {
         this.useMFE = useMFE;
     }

     public CustomUser(String username, String password, Collection<? extends GrantedAuthority> authorities, String totpSecret, boolean useMFE) {
        this.username = username;
        this.password = password;
        this.authorities = authorities;
        this.totpSecret = totpSecret;
        this.useMFE = useMFE;
    }

    public String getTotpSecret() {
        return totpSecret;
    }

    public boolean isUseMFE() {
        return useMFE;
    }

    // 实现 UserDetails 的其他方法
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
