package com.yating.springsecurity.demo.config;

import com.yating.springsecurity.demo.dto.CustomBearerTokenAuthentication;
import com.yating.springsecurity.demo.dto.CustomUser;
import com.yating.springsecurity.demo.enumeration.LoginMethod;
import com.yating.springsecurity.demo.enumeration.TokenType;
import com.yating.springsecurity.demo.util.AuthCommonUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collection;

@Component
@Slf4j
public class CustomOAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @Value("${app.redirect.login-url}")
    private String loginUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;

        OAuth2AuthorizedClient authorizedClient = authorizedClientService
                .loadAuthorizedClient(oauthToken.getAuthorizedClientRegistrationId(), oauthToken.getName());

        String accessToken = authorizedClient.getAccessToken().getTokenValue();
        String refreshToken = authorizedClient.getRefreshToken() != null
                ? authorizedClient.getRefreshToken().getTokenValue()
                : null;

        addCookiesToResponse(response, accessToken, refreshToken);

        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_OK); // 200 OK

        String redirectUrl = "/user/userInfo";
        response.sendRedirect(redirectUrl);
    }


    private void addCookiesToResponse(HttpServletResponse response, String accessToken, String refreshToken) {

        ResponseCookie accessTokenCookie = AuthCommonUtil.createTokenCookie(
                TokenType.ACCESS_TOKEN.getTokenName(),accessToken);
        ResponseCookie refreshTokenCookie = AuthCommonUtil.createTokenCookie(
                TokenType.REFRESH_TOKEN.getTokenName(),refreshToken);

        response.addHeader("Set-Cookie", accessTokenCookie.toString());
        response.addHeader("Set-Cookie", refreshTokenCookie.toString());
    }

}