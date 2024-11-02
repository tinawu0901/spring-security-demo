package com.yating.springsecurity.demo.config;

import com.yating.springsecurity.demo.dto.CustomUser;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        CustomUser user = (CustomUser) authentication.getPrincipal();
        if (user.isUseMFE()) {
            // 跳轉到 TOTP 授權碼頁面
            response.sendRedirect("/totp");
        } else {
            // 正常跳轉到首頁或指定頁面
            response.sendRedirect("/user/userInfo");
        }
    }
}
