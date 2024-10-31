package com.yating.springsecurity.demo.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

@Service
@Slf4j
public class OAuth2TokenService {

    @Value("${spring.security.oauth2.client.registration.test-oauth.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.test-oauth.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.provider.test-oauth.token-uri}")
    private String tokenUri;

    @Value("${spring.security.oauth2.client.provider.test-oauth.logout-uri}")
    private String logoutUri;

    @Autowired
    private RestTemplate restTemplate;

    public String refreshAccessToken(String refreshToken) {
        String requestBody = String.format("grant_type=refresh_token&client_id=%s&client_secret=%s&refresh_token=%s",
                clientId, clientSecret, refreshToken);

        // 設置請求標頭
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // 創建請求實體
        HttpEntity<String> entity = new HttpEntity<>(requestBody, headers);

        try {
            // 發送 POST 請求以獲取新的訪問令牌
            ResponseEntity<String> response = restTemplate.exchange(tokenUri, HttpMethod.POST, entity, String.class);

            // 如果請求成功，從響應中提取新的訪問令牌
            if (response.getStatusCode() == HttpStatus.OK) {
                String body = response.getBody();
                log.info(body);
                ObjectMapper objectMapper = new ObjectMapper();
                JsonNode jsonNode = objectMapper.readTree(body);
                return jsonNode.path("token").asText(); // 提取 token

            }
        } catch (HttpClientErrorException e) {
            // 處理 400 錯誤或其他錯誤
            log.error("Error refreshing access token: " + e.getStatusCode() + " - " + e.getResponseBodyAsString());
        } catch (Exception e) {
            // TODO: handle exception
        }
        return null; // 返回 null 或其他值表示獲取失敗
    }

    public boolean performLogout(String refreshToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type", "application/x-www-form-urlencoded");
        headers.setBasicAuth(clientId, clientSecret);

        String body = String.format("client_id=%s&refresh_token=%s", clientId, refreshToken);
        HttpEntity<String> requestEntity = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<String> responseEntity = restTemplate.exchange(logoutUri, HttpMethod.POST, requestEntity,
                    String.class);

            if (responseEntity.getStatusCode().is2xxSuccessful()) {
                log.info("Logout successful");
                return true;
            } else {
                log.error("Logout failed: " + responseEntity.getBody());
                return false;
            }
        } catch (Exception e) {
            log.error("Logout failed: " + e.getMessage(), e); // 記錄錯誤堆棧跟蹤
            return false;
        }
    }

}