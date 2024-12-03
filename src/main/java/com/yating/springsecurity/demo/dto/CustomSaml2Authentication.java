package com.yating.springsecurity.demo.dto;


import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;

import java.util.Collection;


public class CustomSaml2Authentication extends AbstractAuthenticationToken {
    private final AuthenticatedPrincipal principal;
    private final String saml2Response;
    private final CustomUser customUser;
    private Object details;


    public CustomSaml2Authentication(AuthenticatedPrincipal principal,
                                     String saml2Response,
                                     Collection<? extends GrantedAuthority> authorities,
                                     Object details,
                                     CustomUser customUser) {
        super(authorities);
        this.principal = principal;
        this.saml2Response = saml2Response;
        this.customUser = customUser;
        this.details = details;
        setAuthenticated(true); 
    }

    @Override
    public Object getCredentials() {
        return this.saml2Response;  
    }

    @Override
    public Object getPrincipal() {
        return this.principal;  
    }

    @Override
    public Object getDetails() {
        return this.details;
    }

    public CustomUser getCustomUser() {
        return customUser; 
    }


    public void setDetails(Object details) {
        this.details = details;
    }
}
