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
    private Object details;  // 用于存储额外的细节信息

    // 构造函数
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
        setAuthenticated(true);  // 设置为已认证
    }

    @Override
    public Object getCredentials() {
        return this.saml2Response;  // 返回 SAML2 响应
    }

    @Override
    public Object getPrincipal() {
        return this.principal;  // 返回认证的主体
    }

    @Override
    public Object getDetails() {
        return this.details;  // 返回额外的细节信息
    }

    public CustomUser getCustomUser() {
        return customUser;  // 返回自定义的用户对象
    }

    // 你可以选择提供一个 setter 方法来修改 details
    public void setDetails(Object details) {
        this.details = details;
    }
}
