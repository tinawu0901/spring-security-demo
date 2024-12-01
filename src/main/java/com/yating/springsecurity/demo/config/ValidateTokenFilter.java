package com.yating.springsecurity.demo.config;

import com.yating.springsecurity.demo.enumeration.TokenType;
import com.yating.springsecurity.demo.service.OAuth2TokenService;
import com.yating.springsecurity.demo.util.AuthCommonUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenAuthenticationProvider;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.file.AccessDeniedException;

@Slf4j
@Component
public class ValidateTokenFilter extends OncePerRequestFilter {

    @Autowired
    private OpaqueTokenAuthenticationProvider opaqueTokenAuthenticationProvider;

    @Autowired
    private OAuth2TokenService oAuth2TokenService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Skip token validation if the user is already authenticated (e.g., through username-based login)
        Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
        if (existingAuth != null && existingAuth.isAuthenticated()) {
            log.info("User is already authenticated with username-based login, skipping token validation");
            filterChain.doFilter(request, response);
            return;
        }

        String accessToken = extractTokenFromCookie(request, "access_token");
        String refreshToken = extractTokenFromCookie(request, "refresh_token");
        log.info("Token validation filter triggered");

        if (accessToken != null) {
            processAccessToken(accessToken, refreshToken, response);
        } else {
            handleMissingToken(response);
        }

        filterChain.doFilter(request, response);
    }

    private void processAccessToken(String accessToken, String refreshToken, HttpServletResponse response) throws IOException {
        BearerTokenAuthenticationToken bearerToken = new BearerTokenAuthenticationToken(accessToken);
        try {
            Authentication authentication = opaqueTokenAuthenticationProvider.authenticate(bearerToken);
            log.info("authentication:{}",authentication);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (Exception e) {
            if (refreshToken != null) {
                handleRefreshToken(refreshToken, response);
            } else {
                throw new AccessDeniedException("Access token is invalid and no refresh token available.");
//            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Access token is invalid and no refresh token available.");
            }
        }
    }

    private void handleRefreshToken(String refreshToken, HttpServletResponse response) throws IOException {
        try {
            String newAccessToken = oAuth2TokenService.refreshAccessToken(refreshToken);
            if (newAccessToken != null) {
                BearerTokenAuthenticationToken newBearerToken = new BearerTokenAuthenticationToken(newAccessToken);
                Authentication newAuthentication = opaqueTokenAuthenticationProvider.authenticate(newBearerToken);
                SecurityContextHolder.getContext().setAuthentication(newAuthentication);

                ResponseCookie accessTokenCookie = AuthCommonUtil.createTokenCookie(TokenType.ACCESS_TOKEN.getTokenName(),newAccessToken );
                response.addHeader("Set-Cookie", accessTokenCookie.toString());

                log.info("Setting new token successful!");
            }
            SecurityContextHolder.clearContext();
            throw new AccessDeniedException("Refresh token is invalid or expired.");
//            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Refresh token is invalid or expired.");
        } catch (Exception refreshException) {
            throw new AccessDeniedException("Refresh token is invalid or expired.");
//            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Refresh token is invalid or expired.");
        }
    }

    private void handleMissingToken(HttpServletResponse response) throws IOException {
        log.error("Token is null");
        SecurityContextHolder.clearContext();
        throw new AccessDeniedException("Access denied: Unauthorized access attempt.");
    }

    private String extractTokenFromCookie(HttpServletRequest request, String cookieName) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookieName.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}