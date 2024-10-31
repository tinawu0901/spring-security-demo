package com.yating.springsecurity.demo.controller;

import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
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
}
