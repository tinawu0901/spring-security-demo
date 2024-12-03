package com.yating.springsecurity.demo.dto;

import com.yating.springsecurity.demo.enumeration.LoginMethod;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

public class CustomUser implements UserDetails {
    private String username;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;
    private String totpSecret;
    private boolean useMFE; 

     private LoginMethod loginMethod; 

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

     public CustomUser(String username, String password, Collection<? extends GrantedAuthority> authorities,
                       String totpSecret, boolean useMFE, LoginMethod loginMethod) {
         this.username = username;
         this.password = password;
         this.authorities = authorities;
         this.totpSecret = totpSecret;
         this.useMFE = useMFE;
         this.loginMethod = loginMethod;
     }


    public String getTotpSecret() {
        return totpSecret;
    }

    public boolean isUseMFE() {
        return useMFE;
    }

     public LoginMethod getLoginMethod() {
         return loginMethod;
     }

     public void setLoginMethod(LoginMethod loginMethod) {
         this.loginMethod = loginMethod;
     }


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
