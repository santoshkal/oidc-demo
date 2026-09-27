# OAuth2 vs OIDC - Corrected Overview

## OAuth2: Authorization Only

Authorization framework for **delegated access**. Answers: `Can App X access Resource Y on behalf of User?`

*   User authenticates at the **Authorization Server**, which issues a scoped `access_token` to the **Client** (your app) to call APIs.
*   Uses `scopes` to limit permissions.
*   `access_token` can be opaque, not necessarily a JWT. It is NOT proof of identity. Using it for login is insecure pseudo-authentication.

## OIDC: Authentication

Identity layer **on top of OAuth2**. Answers: `Who is the user?`

*   Extends OAuth2 with the `openid` scope.
*   Adds `id_token` (ALWAYS a JWT) containing identity claims (`sub`, `email`, `profile`) as proof of who the user is.
*   Adds `UserInfo` endpoint and standard identity scopes (`openid`, `profile`, `email`).
*   Client is called the **Relying Party (RP)**, Identity Provider is the **IdP**.

## Key Distinction

*   **OAuth2:** `access_token` = *what* the app can DO.
*   **OIDC:** `id_token` = *who* the user IS.

> If you need login/authentication, use OIDC, not OAuth2 alone.
