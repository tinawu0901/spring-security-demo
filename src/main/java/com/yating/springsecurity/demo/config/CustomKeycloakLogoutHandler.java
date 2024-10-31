package com.yating.springsecurity.demo.config;

import com.yating.springsecurity.demo.service.OAuth2TokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Component
@Slf4j
public class CustomKeycloakLogoutHandler implements LogoutHandler {

    @Value("${spring.security.oauth2.client.registration.test-oauth.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.test-oauth.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.provider.test-oauth.token-uri}")
    private String tokenUri;

    @Autowired
    private OAuth2TokenService oAuth2TokenService;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String refreshToken = getRefreshTokenFromCookies(request); // 從 Cookie 獲取 refresh token

        try {
            if (refreshToken != null) { // 檢查 refresh token 是否存在
                boolean isLogoutSuccessful = oAuth2TokenService.performLogout(refreshToken); // 執行登出

                if (isLogoutSuccessful) {
                    response.setStatus(200);
//					response.sendRedirect("http://localhost:5173/"); // 登出成功，重定向到登錄頁
                } else {
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Logout failed."); // 登出失敗，發送錯誤響應
                }
            } else {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "No refresh token found."); // 如果 refresh token
                log.info("No refresh token found"); // 不存在，發送錯誤響應
            }
        } catch (IOException e) {
            log.error("Error during logout: " + e.getMessage(), e); // 記錄錯誤信息
        }

    }

    private String getRefreshTokenFromCookies(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refresh_token".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

}
