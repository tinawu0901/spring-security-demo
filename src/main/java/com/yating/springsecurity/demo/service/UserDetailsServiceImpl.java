package com.yating.springsecurity.demo.service;

import com.yating.springsecurity.demo.dto.CustomUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;



@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final Map<String, CustomUser> users = new ConcurrentHashMap<>();
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserDetailsServiceImpl(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;

        // 初始化一些測試帳號
        users.put("user", new CustomUser(
                "user",
                passwordEncoder.encode("user"),
                List.of(new SimpleGrantedAuthority("ROLE_USER")),
                null,
                false
        ));

        users.put("user2", new CustomUser(
                "user2",
                passwordEncoder.encode("user2"),
                List.of(new SimpleGrantedAuthority("ROLE_USER")),
                null,
                false
        ));

        users.put("admin", new CustomUser(
                "admin",
                passwordEncoder.encode("adminpass"),
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")),
                "totp-secret-admin",
                true
        ));
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        CustomUser user = users.get(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }
        return user;
    }

    // 新增用戶
    public void addUser(String username, String password, boolean useMFE) {
        CustomUser user = new CustomUser(
                username,
                passwordEncoder.encode(password),
                List.of(new SimpleGrantedAuthority("ROLE_USER")),
                "totp-secret",  // 您的 TOTP 秘鑰
                useMFE
        );
        users.put(username, user);
    }

    // 更新用戶
    public void updateUser(String username, CustomUser user) {
        if (users.containsKey(username)) {
            users.put(username, user);
        } else {
            throw new IllegalArgumentException("User not found: " + username);
        }
    }

    // 刪除用戶
    public void deleteUser(String username) {
        users.remove(username);
    }
}
