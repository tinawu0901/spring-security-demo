package com.yating.springsecurity.demo.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseCookie;

import java.time.Duration;

public class AuthCommonUtil {

    private static final String COOKIE_DOMAIN = "localhost";

    public static ResponseCookie createTokenCookie(String cookieName, String cookieValue) {
        return ResponseCookie.from(cookieName, cookieValue).domain(COOKIE_DOMAIN).httpOnly(true).sameSite("Lax")
                .path("/").secure(true)
                .maxAge(cookieName.equals("access_token") ? Duration.ofHours(1) : Duration.ofDays(7)).build();
    }


    /**
     * Retrieves the value of a cookie by its name from the request.
     *
     * @param request the HttpServletRequest containing the cookies
     * @param cookieName the name of the cookie to retrieve
     * @return the value of the cookie, or null if not found
     */
    public static String getCookieValue(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookieName.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
