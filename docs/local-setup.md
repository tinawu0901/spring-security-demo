# Local setup

Run all commands from the repository root. Use Java 17 or later, Maven, and Docker with Compose. Check `java -version`, `mvn -version` and `docker compose version` before starting. If Maven cannot find Java, set `JAVA_HOME` to your JDK installation.

## Environment variables

The application reads process environment variables. Spring Boot does not automatically load a `.env` file in this project. Set variables in the terminal that will run Maven, or in your IDE's run configuration. Docker Compose can use these same terminal variables.

| Variable | Purpose | Default |
| --- | --- | --- |
| `KEYCLOAK_CLIENT_SECRET` | Confidential OIDC client secret; also used for introspection | Required |
| `LDAP_ADMIN_PASSWORD` | LDAP admin bind password; also used when creating the LDAP container | Required |
| `KEYCLOAK_BASE_URL` | Keycloak server URL | `http://localhost:8080` |
| `KEYCLOAK_REALM` | Keycloak realm | `test-oauth` |
| `KEYCLOAK_CLIENT_ID` | OIDC client ID | `demo-api` |
| `LDAP_URL` | LDAP server URL | `ldap://localhost:8389` |
| `LDAP_BASE` | LDAP search base | `dc=example,dc=org` |
| `LDAP_ADMIN_DN` | Admin bind DN | `cn=admin,dc=example,dc=org` |
| `SAML_SP_PRIVATE_KEY` | Spring resource location for the SP private key | `file:./local-secrets/rp.key` |
| `SAML_SP_CERTIFICATE` | Matching SP public certificate | `file:./local-secrets/rp.crt` |
| `SERVER_PORT` | Application port | `8081` |

PowerShell example (replace the placeholders with your local values):

```powershell
$env:KEYCLOAK_CLIENT_SECRET = "your-new-oidc-client-secret"
$env:LDAP_ADMIN_PASSWORD = "your-local-ldap-password"
```

Do not commit populated credential files, private keys or TOTP provisioning QR codes. The `local-secrets/` directory is ignored by Git. Credentials previously published with older versions of the repository must be replaced; removing a file does not remove it from Git history.

## Keycloak

The original demo used Keycloak 26.0.0. The command below keeps that version for reproducing the demo; it is not a recommendation for a production deployment.

Set a local admin password, then start a development instance:

```powershell
$env:KC_BOOTSTRAP_ADMIN_PASSWORD = "your-local-keycloak-admin-password"
docker run --name spring-security-keycloak -p 127.0.0.1:8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD -v spring-security-keycloak-data:/opt/keycloak/data quay.io/keycloak/keycloak:26.0.0 start-dev
```

Open `http://localhost:8080` and create:

1. Realm `test-oauth` (or set `KEYCLOAK_REALM` to your realm).
2. A confidential OpenID Connect client named `demo-api`, with the authorization-code/standard flow enabled. Allow redirect URI `http://localhost:8081/login/oauth2/code/test-oauth`. Copy its newly generated secret into `KEYCLOAK_CLIENT_SECRET` locally.
3. A SAML client whose client ID matches the application's service-provider entity ID. Use the application's SP metadata to configure its entity ID, assertion consumer URL and public signing certificate. The application callback is `/login/saml2/sso/test-oauth`; its registration ID remains `test-oauth` even if the realm name changes.
4. Test users for OIDC and SAML login.

Spring obtains IdP metadata from `/realms/<realm>/protocol/saml/descriptor`, including the IdP verification certificate. The application's signing certificate belongs to the service provider and must match its private key; it is separate from Keycloak's IdP certificate.

The application loads OIDC discovery and SAML metadata during startup, so configure and start Keycloak before Spring Boot. This repository does not include a realm export or automatic client provisioning.

## SAML signing credentials

Supply a new PEM private key and its matching X.509 certificate in `local-secrets/`. The private key must be in PKCS#8 format. Register only the public certificate with the Keycloak SAML client.

If OpenSSL is installed, a local self-signed pair can be generated with:

```sh
mkdir local-secrets
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out local-secrets/rp.key
openssl req -new -x509 -key local-secrets/rp.key -out local-secrets/rp.crt -days 365 -subj "/CN=spring-security-demo"
```

Skip `mkdir` if the directory already exists. Self-signed credentials here are for a local demonstration. Do not reuse keys that were previously committed.

## LDAP

With `LDAP_ADMIN_PASSWORD` set in the same terminal:

```sh
docker compose -f src/main/resources/dockerfile/docker-compose.yml up -d
```

The Compose file uses `example.org`, corresponding to base DN `dc=example,dc=org`. phpLDAPadmin is available at `http://localhost:8086`; bind with `cn=admin,dc=example,dc=org` and your chosen LDAP admin password.

Create the directory tree expected by the existing bind patterns:

```text
dc=example,dc=org
└── ou=ITteam
    ├── cn=PG
    │   └── cn=<test-user>
    └── cn=SA
        └── cn=<test-user>
```

The user entries need valid LDAP object classes and passwords. Use usernames that do not exist in the local in-memory user map when demonstrating LDAP fallback. Group lookup uses `ou=ITteam`. Users and groups are not seeded automatically.

LDAP data and configuration use named volumes mapped to `/var/lib/ldap` and `/etc/ldap/slapd.d`, following the [OpenLDAP image documentation](https://github.com/osixia/container-openldap). The compose configuration uses new volume names; it does not migrate any existing LDAP data. Use `docker compose ... down` without `-v` to preserve data.

## Running the application

```sh
mvn spring-boot:run
```

Open `http://localhost:8081/login`. The in-memory demo accounts `user` / `user` and `user2` / `user2` are deliberate local examples, not real credentials. An additional demo admin exists in the source, but its pre-filled TOTP value is a placeholder rather than a valid enrolment.

The existing implementation mixes sessions with secure token cookies and retains diagnostic token endpoints. Its custom token filter can reject requests without token cookies, and TOTP completion is not enforced across every protected route. Do not interpret the setup instructions as verification that these flows work; authentication behaviour needs a separate review and end-to-end testing before deployment.
