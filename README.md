# Signaturesi Accounts

The central identity platform for the Signaturesi ecosystem.

Accounts provides a secure custom **Bean ID** authentication system for NEO, Bean, and future Signaturesi products.

---

# Current Status

## Current Stage

✅ Custom Bean ID Authentication (Working)

Implemented:

- Bean ID Registration
- Bean ID Login
- Username Availability Check
- Session Creation
- Session Validation
- Logout
- Bean Profiles
- Custom Authentication
- Secure HttpOnly Cookies

Supabase Auth is **NOT** used.

---

# Authentication

Users create an identity like:

```
leo11@bean
```

No email verification.

No OTP.

No Magic Links.

No Supabase Auth.

Everything uses our own authentication system.

---

# Technology

Frontend

- HTML
- CSS
- JavaScript

Backend

- Vercel Serverless Functions

Database

- Supabase PostgreSQL

Password Hashing

- Argon2id

Sessions

- Secure HttpOnly Cookies
- Opaque Session Tokens
- SHA-256 Token Hashing

---

# Database

Current authentication tables:

```
bean_users
bean_credentials
bean_sessions
bean_profiles
```

### bean_users

Stores Bean ID account.

### bean_credentials

Stores Argon2id password hashes.

### bean_sessions

Stores active sessions.

### bean_profiles

Stores profile information.

---

# API

## Check Username

```
GET /api/auth/check-username
```

Example

```
GET /api/auth/check-username?username=leo11
```

---

## Register

```
POST /api/auth/register
```

Example

```json
{
  "username":"leo11",
  "password":"StrongPassword123!"
}
```

---

## Login

```
POST /api/auth/login
```

Example

```json
{
  "username":"leo11",
  "password":"StrongPassword123!"
}
```

---

## Session

```
GET /api/auth/session
```

Returns

```json
{
  "authenticated": true,
  "user": {
    "id":"uuid",
    "username":"leo11",
    "displayName":"leo11",
    "beanId":"leo11@bean"
  }
}
```

---

## Logout

```
POST /api/auth/logout
```

Deletes the current session and clears the secure cookie.

---

# Environment Variables

```
SUPABASE_URL

SUPABASE_SERVICE_ROLE_KEY

SESSION_COOKIE_NAME

SESSION_SECRET

IP_HASH_SECRET

APP_ORIGIN

NODE_ENV
```

---

# Security

Implemented

✅ Custom Authentication

✅ Argon2id Password Hashing

✅ HttpOnly Cookies

✅ Secure Cookies

✅ SameSite=Lax

✅ SHA-256 Session Hashes

✅ Random Session Tokens

✅ Server-only Service Role Key

✅ Session Expiration

✅ Session Revocation

✅ No Supabase Auth

---

# Not Yet Implemented

- Password Reset
- Account Recovery
- Email Linking
- MFA
- Rate Limiting
- Admin Dashboard
- Audit Dashboard
- Session Manager
- Device Manager

---

# Ecosystem

```
accounts.signaturesi.com

↓

Bean Authentication

↓

neo.signaturesi.com

↓

bean.signaturesi.com

↓

Future Signaturesi Products
```

Every product shares the same Bean ID.

---

# Product Goal

One account.

One Bean ID.

One secure identity.

Entire Signaturesi ecosystem.

---

# Roadmap

## Phase 1 ✅

- Custom Authentication
- Registration
- Login
- Sessions
- Profiles

## Phase 2

- NEO Integration
- Bean Integration
- Shared Authentication

## Phase 3

- Organizations
- Teams
- Permissions
- Developer APIs

## Phase 4

- Complete Signaturesi Identity Platform

---

# Repository Structure

```
api/
    auth/
        register.js
        login.js
        logout.js
        session.js
        check-username.js

lib/

public/

index.html
```

---

# License

Private

Copyright © Signaturesi

All Rights Reserved.
