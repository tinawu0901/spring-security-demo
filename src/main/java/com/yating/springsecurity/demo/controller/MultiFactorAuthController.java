package com.yating.springsecurity.demo.controller;

import com.yating.springsecurity.demo.dto.CustomUser;
import com.yating.springsecurity.demo.service.GAService;
import com.yating.springsecurity.demo.service.UserDetailsServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;

@Controller
@Slf4j
public class MultiFactorAuthController {

    @Autowired
    private  UserDetailsServiceImpl userDetailsServiceImpl;

    @Autowired
    private GAService gaService; // 引入 GAService


    @RequestMapping("/user/userInfo")
    public String userInfo(Model model, Principal principal) {
        // 獲取當前用戶的名稱
        String username = principal.getName();

        // 從 UserDetailsServiceImpl 中獲取 CustomUser
        CustomUser customUser = (CustomUser) userDetailsServiceImpl.loadUserByUsername(username);

        if (customUser != null) {
            log.info("CustomUser: {}", customUser);
            model.addAttribute("username", customUser.getUsername());
            model.addAttribute("useMFE", customUser.isUseMFE());
            return "userInfo";
        } else {
            // 處理未找到 CustomUser 的情況，重定向到登入頁面
            return "redirect:/login?error=notAuthenticated";
        }
    }

    @PostMapping("/enableMFE")
    public String enableMFE(@RequestParam String username, Model model) {
        // 獲取用戶的 TOTP 秘鑰
        CustomUser customUser = (CustomUser) userDetailsServiceImpl.loadUserByUsername(username);

        if (customUser == null) {
            // 處理用戶未找到的情況
            model.addAttribute("error", "User not found");
            return "error"; // 返回錯誤頁面
        }

        String secret = customUser.getTotpSecret(); // 獲取用戶的 TOTP 秘鑰

        if (secret == null || secret.isEmpty()) {
            // 如果用戶尚未設置 TOTP 秘鑰，則生成一個新的秘鑰
            secret = gaService.generateKey();
            customUser.setTotpSecret(secret); // 設置用戶的 TOTP 秘鑰

            // 生成 QR Code 的 URL
            String qrUrl = gaService.generateQRUrl(secret, username);
            if (qrUrl == null) {
                model.addAttribute("error", "Error generating QR Code");
                return "error"; // 返回錯誤頁面
            }

            // 在模型中添加 QR Code
            model.addAttribute("qrCode", qrUrl);
            model.addAttribute("username", username);
            model.addAttribute("useMFE", customUser.isUseMFE()); // 當前還沒有啟用 MFE
            return "enableMFE"; // 返回新的 enableMFE 頁面
        }

        // 如果已經設置了秘鑰，則不顯示 QR Code
        model.addAttribute("qrCode", null); // 不顯示 QR Code
        model.addAttribute("username", username);
        model.addAttribute("useMFE", customUser.isUseMFE()); // 更新用戶的 MFE 狀態
        return "userInfo"; // 返回用戶信息頁面
    }



    // 驗證 TOTP 授權碼
    @PostMapping("/validateCode")
    public String validateCode(@RequestParam String username, @RequestParam int code, Model model) {
        // 獲取用戶的 TOTP 密鑰
        CustomUser customUser = (CustomUser) userDetailsServiceImpl.loadUserByUsername(username);

        if (customUser == null) {
            model.addAttribute("error", "User not found");
            return "error"; // 返回錯誤頁面
        }
        log.info("username:{},totpsecret is :{}",customUser.getUsername(),customUser.getTotpSecret());
        // 驗證輸入的驗證碼
        boolean isValid = gaService.isValid(customUser.getTotpSecret(), code);
        if (!isValid) {
            model.addAttribute("error", "Invalid code. Please try again.");
            model.addAttribute("username", username);
            return "totpVerification"; // 返回 TOTP 驗證頁面，並顯示錯誤信息
        }

        // 如果驗證成功，將 useMFE 設置為 true
        customUser.setUseMFE(true);
     //   userDetailsServiceImpl.save(customUser); // 保存用戶的 MFE 狀態

        // 完成完全認證，設置 SecurityContext
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(customUser, null, customUser.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        return "redirect:/user/userInfo"; // 重定向到用戶信息頁面
    }
    // 顯示 TOTP 驗證表單
    @GetMapping("/totp")
    public String totpVerificationForm(Model model, Principal principal) {
        // 獲取當前用戶的用戶名
        String username = principal.getName();

        // 從 UserDetailsServiceImpl 中獲取 CustomUser
        CustomUser customUser = (CustomUser) userDetailsServiceImpl.loadUserByUsername(username);

        // 將用戶名添加到模型中
        model.addAttribute("username", customUser.getUsername());

        return "totpVerification"; // 返回修改後的 TOTP 驗證頁面
    }


    @PostMapping("/totp")
    public String validateTotpCode(@RequestParam String username, @RequestParam int code, Model model) {
        CustomUser customUser = (CustomUser) userDetailsServiceImpl.loadUserByUsername(username);

        if (customUser != null && gaService.isValid(customUser.getTotpSecret(), code)) {
            // If TOTP is valid, authenticate the user
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(customUser, null, customUser.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);
            return "redirect:/user/userInfo"; // Redirect to the protected userInfo page
        } else {
            model.addAttribute("error", "Invalid authorization code. Please try again.");
            return "totpVerification";
        }
    }
}
