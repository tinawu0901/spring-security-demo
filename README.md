# Spring Security with Keycloak, SAML2, OAuth2, and LDAP Integration
## 簡介
本專案展示了如何整合多種驗證機制，包括 Keycloak、SAML2、OAuth2、和 LDAP，並支持自定義驗證邏輯。適用於需要多重驗證方式的企業應用場景。
## 功能
- 支援以下登入方式：
  - LDAP：透過 OpenLDAP 進行用戶驗證。
  - OAuth2：使用 Keycloak 提供的 OAuth2 驗證。
  - SAML2：Keycloak 作為 SAML2 身分提供者。
  - 自定義驗證：模擬從資料庫讀取的驗證。
-  多因子驗證：支援 TOTP（Time-based One-Time Password）。
- 統一登出機制：處理不同驗證方式的登出需求。
## 快速啟動
## 系統需求
- JDK 17+
- Docker / Docker Compose
- Maven
## 啟動步驟
1. clone 專案  

    ``` 
    git clone https://github.com/tinawu0901/spring-security-demo.git
    ```

2. 啟動 Keycloak 

    ```
    docker run -p 8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin -v keycloak:/opt/keycloak/data  quay.io/keycloak/keycloak:26.0.0  start-dev
    ```

    創建 OpenID Connect client 和  saml2 client
    及創建測試帳號
3. 啟動LDAP

   cd 到src\main\resources\dockerfile下   
  `docker-compose up -d`
  根據參考資料 創建測試帳號
 
4. 啟動 Spring Boot 專案  

    `mvn spring-boot:run`
## 畫面

1. 登入頁面
![image](https://github.com/tinawu0901/spring-security-demo/blob/main/src/main/resources/image/LoginPage.png)

2. 客製化方式登入
![image](https://github.com/tinawu0901/spring-security-demo/blob/main/src/main/resources/image/CuStomUserInfo.png)
- 啟動MFE
![image](https://github.com/tinawu0901/spring-security-demo/blob/main/src/main/resources/image/EnableMFE.png)
- 驗證成功並成功開啟
![image](https://github.com/tinawu0901/spring-security-demo/blob/main/src/main/resources/image/EnableMFESucees.png)
- 重新登入後須進行驗證
![image](https://github.com/tinawu0901/spring-security-demo/blob/main/src/main/resources/image/MFEValidated.png)

3. LDAP方式登入

![image](https://github.com/tinawu0901/spring-security-demo/blob/main/src/main/resources/image/LDAPUserInfo.png)

4. Saml2方式登入

- 透過keycloak登入

![image](https://github.com/tinawu0901/spring-security-demo/blob/main/src/main/resources/image/image.png)

- 成功登入後導回自定義頁面

![image](https://github.com/tinawu0901/spring-security-demo/blob/main/src/main/resources/image/Saml2UserInfo.png)


5. Oauth2方式登入

- 透過keycloak登入

![image](https://github.com/tinawu0901/spring-security-demo/blob/main/src/main/resources/image/image.png)

- 成功登入後導回自定義頁面
![image](https://github.com/tinawu0901/spring-security-demo/blob/main/src/main/resources/image/Oauth2UserInfo.png)

6. 成功登出頁面
![image](https://github.com/tinawu0901/spring-security-demo/blob/main/src/main/resources/image/LogoutSuccess.png)



## 參考資料

[1]: <https://chrislee0728.medium.com/%E4%BD%BF%E7%94%A8-docker-%E5%BB%BA%E7%BD%AE-ldap-%E7%B3%BB%E7%B5%B1-82370c53bc9f>  
[2]:<https://piotrminkowski.com/2024/10/28/spring-boot-with-saml2-and-keycloak/>
[3]:<https://medium.com/@skarki2/implementing-totp-using-google-auth-in-spring-boot-70cc4381c5e1>

- [使用 Docker 建置 LDAP 系統][1]
- [Spring Boot with SAML2 and Keycloak][2]
- [Implementing 2Factor TOTP Using Google Auth in Spring Boot][3]
## 代辦事項
- [x] keycloack 及LDAP dockerfile
- [x] 參考文件
- [x] 畫面截圖
- [ ] 遇到問題
- [ ] openID token描述
