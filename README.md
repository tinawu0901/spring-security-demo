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
`git clone https://github.com/tinawu0901/spring-security-demo.git `
1. 啟動 Keycloak 和 LDAP（Docker Compose）  
`docker-compose up -d`
1. 啟動 Spring Boot 專案  
`mvn spring-boot:run`
1. 測試登入
 - 使用範例用戶進行測試（預設用戶和密碼見下方）。
  




- [ ] keycloack 及LDAP dockerfile
- [ ] 測試用戶設定
- [ ] 啟動畫面截圖
- [ ] 參考文件
- [ ] 遇到問題
- [ ] openId token描述
