package com.yating.springsecurity.demo.dto;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public class CustomBearerTokenAuthentication  extends BearerTokenAuthentication {
    private final CustomUser customUser;

    public CustomBearerTokenAuthentication(OAuth2AuthenticatedPrincipal principal,
                                           OAuth2AccessToken credentials,
                                           Collection<? extends GrantedAuthority> authorities,
                                           CustomUser customUser) {
        super(principal, credentials, authorities);
        this.customUser = customUser;
    }


    public CustomUser getCustomUser() {
        return customUser;
    }


}
