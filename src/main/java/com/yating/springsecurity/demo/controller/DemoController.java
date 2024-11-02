package com.yating.springsecurity.demo.controller;

import com.yating.springsecurity.demo.enumeration.TokenType;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@Slf4j
@RequestMapping("demo")
public class DemoController {

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @Autowired
    private OAuth2AuthorizedClientManager authorizedClientManager;
    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @GetMapping("/test")
    public String  sayHello() {
        return "Hello!";
    }

    @GetMapping("/getUserInfo")
    public ResponseEntity<Map<String,String>> getUserInfo(Authentication authentication, HttpServletResponse httpServletResponse) {
        if(! (authentication instanceof BearerTokenAuthentication)){
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error","UNAUTHORIZED:Not authenticated as Bearer token"));
        }
        BearerTokenAuthentication bearerTokenAuthentication = (BearerTokenAuthentication) authentication;
         String accessToken  = bearerTokenAuthentication.getToken().getTokenValue();

        // 获取 OAuth2AuthorizedClient
        OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                "test-oauth", bearerTokenAuthentication.getName());

        // 检查是否有 refresh_token
        String refreshToken = null;
        if (authorizedClient != null && authorizedClient.getRefreshToken() != null) {
            refreshToken = authorizedClient.getRefreshToken().getTokenValue();
        }

        OAuth2IntrospectionAuthenticatedPrincipal introspectionPrincipal =
                (OAuth2IntrospectionAuthenticatedPrincipal) bearerTokenAuthentication.getPrincipal();

        String username = introspectionPrincipal.getAttribute("preferred_username");
        String email = introspectionPrincipal.getAttribute("email");


        Map<String, String> responseBody = new HashMap<>();
        responseBody.put("access_token", accessToken);
        responseBody.put("refresh_token", refreshToken != null ? refreshToken : "No refresh token");
        responseBody.put("username", username);
        responseBody.put("email", email);

        return ResponseEntity.ok(responseBody);

    }


    @GetMapping("/getNewToken")
    public String refreshAccessToken(@RequestHeader("Cookie") String cookie,Authentication authentication) {

        String accessTokenValue = extractTokenFromCookie(cookie, TokenType.ACCESS_TOKEN.getTokenName());
        String refreshTokenValue = extractTokenFromCookie(cookie, TokenType.REFRESH_TOKEN.getTokenName());


        if (!(authentication instanceof BearerTokenAuthentication)) {
            throw new IllegalStateException("Authentication is not BearerTokenAuthentication.");
        }

        BearerTokenAuthentication bearerTokenAuthentication = (BearerTokenAuthentication) authentication;
        String oldAccessToken = bearerTokenAuthentication.getToken().getTokenValue();

        // Load OAuth2AuthorizedClient
        OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                "test-oauth", bearerTokenAuthentication.getName());
//
//        // Check if authorizedClient is null
//        if (authorizedClient == null) {
////            logger.error("Authorized client is null for principal: {}", bearerTokenAuthentication.getName());
//            throw new IllegalStateException("Authorized client not found.");
//        }

        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId("test-oauth");
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessTokenValue, null, null);
        // Get refresh token
        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(refreshTokenValue, null);
//        if (refreshToken == null) {
////            throw new IllegalStateException("Refresh token is not available.");
//            refreshToken = new OAuth2RefreshToken(refreshTokenValue, null);
//        }

        // Create refresh token request
        OAuth2RefreshTokenGrantRequest grantRequest = new OAuth2RefreshTokenGrantRequest(
                clientRegistration,
                accessToken,
                refreshToken // Provide user principalName
        );
        DefaultRefreshTokenTokenResponseClient defaultRefreshTokenTokenResponseClient  = new DefaultRefreshTokenTokenResponseClient();
        // Use the response client to get new access token
        OAuth2AccessTokenResponse tokenResponse = defaultRefreshTokenTokenResponseClient.getTokenResponse(grantRequest);

        // Get new access token
        OAuth2AccessToken newAccessToken = tokenResponse.getAccessToken();

        // Return old and new access tokens as a string
        return String.format("Old Access Token: %s\nNew Access Token: %s", oldAccessToken, newAccessToken.getTokenValue());
    }

    private String extractTokenFromCookie(String cookie, String tokenName) {
        String[] cookies = cookie.split(";");
        for (String c : cookies) {
            String[] parts = c.trim().split("=");
            if (parts.length == 2 && parts[0].equals(tokenName)) {
                return parts[1];
            }
        }
        return null; // 若未找到 token，返回 null
    }
}
