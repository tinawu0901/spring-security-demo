package com.yating.springsecurity.demo.config;

import com.yating.springsecurity.demo.dto.CustomSaml2Authentication;
import com.yating.springsecurity.demo.dto.CustomUser;
import com.yating.springsecurity.demo.enumeration.LoginMethod;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

public class CustomSaml2LoginSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        DefaultSaml2AuthenticatedPrincipal samlAuthentication = (DefaultSaml2AuthenticatedPrincipal) authentication.getPrincipal();

        CustomUser customUser = new CustomUser(
                samlAuthentication.getName(),
                null,
                null,
                null,
                false,
                LoginMethod.SAML2
        );
        CustomSaml2Authentication newAuthentication = new CustomSaml2Authentication(
                (DefaultSaml2AuthenticatedPrincipal) authentication.getPrincipal(),
                ((Saml2Authentication) authentication).getSaml2Response(),
                authentication.getAuthorities(),
                authentication.getDetails(),
                customUser
        );
        SecurityContextHolder.getContext().setAuthentication(newAuthentication);
        String redirectUrl = "/user/userInfo";
        response.sendRedirect(redirectUrl);
    }
}
