# authen-express

Express controllers for authentication APIs.

`authen-express` is a lightweight library built on top of **Express** and **jsonwebtoken** for implementing authentication endpoints. It provides ready-to-use controllers for login, token refresh, and privilege APIs while keeping authentication business logic independent from the HTTP layer.

Unlike complete authentication frameworks, `authen-express` does **not** authenticate users itself. Instead, it delegates authentication to an injected service (such as **authen-service**) and focuses only on HTTP concerns.

---

## Features

- 🔐 Login controller
- 🔄 Refresh access token
- 🍪 Cookie-based authentication
- 📱 Token-based authentication for mobile applications
- 🚀 Supports React, Angular, Vue, Android and iOS
- 🔌 Built for Express
- 🛡 Secure cookie defaults
- 🔑 JWT generation
- ⚙️ Configurable JWT payload mapping
- 🔒 Optional password decryption
- 📋 Privilege API controller
- 🎯 Framework-independent authentication

---

## Installation

```bash
npm install authen-express
```

or

```bash
yarn add authen-express
```

---

# Philosophy

`authen-express` handles only the **HTTP layer**.

It does **not** implement:

- Password verification
- Account lockout
- Password expiration
- Two-factor authentication
- User repository
- Authentication policies

These responsibilities belong to an authentication domain library such as **authen-service**.

```
   HTTP Request
         │
         ▼
  authen-express
         │
         ▼
Authentication Service
  (authen-service)
         │
         ▼
      Database
```

This separation follows the principles of **Clean Architecture**.

---

# Architecture

```
      React
     Angular
       Vue
     Android
       iOS

        │

        ▼

  authen-express

        │

        ▼

  authen-service

        │

        ▼

     Database
```

For Server-Side Rendering applications, `jsonwebtoken-express` can be used to authenticate incoming requests.

```
      Browser

         ↓

jsonwebtoken-express

         ↓

      Express

         ↓

   authen-express

         ↓

   authen-service
```

---

# Quick Start

```typescript
import express from "express";
import { AuthenticationController } from "authen-express";
import { authenticate } from "./authentication";

const app = express();

const controller = new AuthenticationController(
    authenticate,
    console.error,
    "access_token",
    process.env.JWT_SECRET!,
    15 * 60 * 1000,
    "lax",
    {
        id: "sub",
        username: "username"
    },
    "remember_token",
    process.env.REMEMBER_SECRET!,
    30 * 24 * 60 * 60 * 1000,
    true
);

app.post("/login", controller.authenticate);
```

---

# Authentication Flow

```
     Client

        ↓

   POST /login

        ↓

 authen-express

        ↓

 authen-service

        ↓

Authentication Result

        ↓

  Generate JWT

        ↓

  Cookie or JSON

        ↓

      Client
```

---

# Cookie Mode (SSR)

When `cookie = true`, the controller stores the access token in an HTTP-only cookie.

```
      Browser

          ↓

     POST /login

          ↓

      Set Cookie

          ↓

Redirect or Render Page
```

Ideal for:

- Server-Side Rendering
- Traditional MVC
- Cookie-based authentication

---

# Token Mode (SPA / Mobile)

When `cookie = false`, the generated JWT is returned in the response body.

```json
{
    "status": 0,
    "token": "eyJhbGciOi..."
}
```

Ideal for:

- React
- Angular
- Vue
- Android
- iOS
- REST APIs

---

# Password Decryption

Some applications encrypt passwords before sending them to the server.

`authen-express` supports optional password decryption.

```typescript
const controller = new AuthenticationController(
    authenticate,
    console.error,
    ...,
    decryptPassword
);
```

If no decryption function is provided, passwords are used as received.

---

# JWT Payload Mapping

The authenticated account can be mapped into a custom JWT payload.

Example:

```typescript
{
    id: "sub",
    username: "name",
    language: "lang"
}
```

Generated payload:

```json
{
    "sub": "100",
    "name": "john",
    "lang": "en"
}
```

This allows applications to minimize token size while preserving compatibility with existing JWT conventions.

---

# Controllers

## AuthenticationController

Authenticates users and generates JWT tokens.

```typescript
app.post("/login", controller.authenticate);
```

Responsibilities:

- Validate request
- Optional password decryption
- Call authentication service
- Generate JWT
- Generate remember token
- Return cookie or JSON

---

## TokenController

Refreshes expired access tokens using a remember token.

```typescript
app.post("/refresh", tokenController.refresh);
```

Responsibilities:

- Verify remember token
- Generate new access token
- Update cookie

---

## PrivilegeController

Returns application privileges.

```typescript
app.get("/privileges", privilegeController.all);
```

---

# Supporting Two Authentication Styles

## Cookie-based

Suitable for:

- SSR
- MVC
- Browser applications

```
Browser

   ↓

 Cookie

   ↓

 Server
```

---

## Token-based

Suitable for:

- React
- Angular
- Vue
- Android
- iOS

```
       Client

         ↓

Authorization Header

         ↓

       Server
```

One controller supports both approaches.

---

# Integration with authen-service

`authen-express` delegates authentication to **authen-service**.

| authen-service | authen-express |
|----------------|------------------------|
| Password verification | Login endpoint |
| Password expiration | JWT generation |
| Account lockout | Cookie handling |
| Two-factor authentication | HTTP controllers |
| Privilege loading | JSON responses |
| Authentication policies | Express integration |

---

# Integration with jsonwebtoken-express

For Server-Side Rendering applications:

```
      Login

        ↓

  authen-express

        ↓

    JWT Cookie

        ↓

     Browser

        ↓

   Next Request

        ↓

 jsonwebtoken-express

        ↓

Authenticated Request

        ↓

    Controller
```

The two libraries complement each other.

- **authen-express** authenticates users.
- **jsonwebtoken-express** authenticates requests.

---

# Security

The library provides:

- JWT generation
- HTTP-only cookies
- Secure cookies
- SameSite support
- Remember tokens
- Optional encrypted passwords

The library intentionally does **not** implement:

- Password verification
- User repository
- Authorization
- OAuth
- OpenID Connect
- Session management

---

# Use Cases

`authen-express` is ideal for:

- Express applications
- REST APIs
- React backends
- Angular backends
- Vue backends
- Android backends
- iOS backends
- Cookie-based authentication
- JWT authentication

---

# Design Principles

- Clean Architecture
- Separation of Concerns
- Dependency Injection
- HTTP Adapter Pattern
- Framework-independent Authentication
- Cookie or Token Authentication
- Minimal API Surface

---

# Related Packages

## authen-service

Framework-independent authentication domain library.

Features:

- Password authentication
- Password expiration
- Account lockout
- Two-factor authentication
- Authentication policies

---

## jsonwebtoken-express

Express middleware for authenticating incoming requests using JWT cookies.

Primarily designed for Server-Side Rendering applications.

---

### security-express

Express authorization middleware for protecting authenticated routes.

---

# The Big Picture of core-ts ecosystem
### HTTP / Transport Layer
- [jsonwebtoken-express](https://www.npmjs.com/package/jsonwebtoken-express) — verify JWT cookies, renew access tokens, SSR middleware.
- [authentication-express](https://www.npmjs.com/package/authentication-express) — login, refresh, privilege endpoints for React / Angular / Android / iOS clients.
- [security-express](https://www.npmjs.com/package/security-express) — route authorization and request protection.

### Authentication Domain Layer
- [authen-service](https://www.npmjs.com/package/authen-service) — password verification, lockout, expiry, 2FA, access rules, privilege loading.

### Identity / Account Services
- [signup-service](https://www.npmjs.com/package/signup-service) — user registration workflow.
- [password-service](https://www.npmjs.com/package/password-service) — password change / reset logic.

### Persistence Layer
- [sql-core](https://www.npmjs.com/package/sql-core) + [mysql2-core](https://www.npmjs.com/package/mysql2-core) (from a broader ecosystem).

# Spring ecosystem equivalent
### HTTP / Web Security
- SecurityFilterChain
- JWT / OAuth filters
- Remember-me services

### Authentication Core
- AuthenticationManager
- AuthenticationProvider
- PasswordEncoder
- UserDetailsService

### Identity Management
- Custom registration service.
- Password reset service.

### Persistence
- Spring Data / JDBC / JPA repositories

# Direct Mapping with Java Spring

| core-ts ecosystem          | Spring Equivalent |
|----------------------------|-------------------|
| **authen-service**         | AuthenticationProvider + UserDetailsService + Password Policy |
| **password-service**       | Password Reset / Change Service |
| **signup-service**         | Registration Service |
| **authentication-express** | Login Controller + Token Issuance Endpoint |
| **jsonwebtoken-express**   | JWT Authentication Filter + Remember-Me Filter |
| **security-express**       | Authorization Filter / Access Decision Layer |
---

## The Most Important Difference
Spring Security starts from the web framework and moves inward
``` text
HTTP → Filters → Authentication → Domain
```

Your ecosystem starts from the domain and moves outward.
``` text
Domain → authen-service → Express adapters → HTTP
```

That is a fundamentally different architectural philosophy.

## Feature Coverage Comparison

| Capability | core-ts ecosystem | Spring Security |
|------------|:--------------:|:---------------:|
| Username/password authentication | ✅ | ✅ |
| JWT generation | ✅ | ✅ |
| JWT verification | ✅ | ✅ |
| Cookie authentication | ✅ | ✅ |
| SPA authentication | ✅ | ✅ |
| Mobile authentication | ✅ | ✅ |
| Server-Side Rendering (SSR) | ✅ | ✅ |
| Remember token | ✅ | ✅ |
| Access token renewal | ✅ | ✅ |
| Account lockout | ✅ | Custom |
| Password expiration | ✅ | Custom |
| Password reset | ✅ | Custom |
| User registration | ✅ | Custom |
| Two-factor authentication | ✅ | Custom |
| Privilege hierarchy | ✅ | Partial |
| Role-based authorization | ✅ | ✅ |
| Route authorization | ✅ | ✅ |
| OAuth2 / OpenID Connect | ❌ | ✅ |
| LDAP / Active Directory | ❌ | ✅ |
| SAML | ❌ | ✅ |
| Kerberos | ❌ | ✅ |
| X.509 Authentication | ❌ | ✅ |
| CSRF protection | Express middleware | ✅ |
| Session fixation protection | Express middleware | ✅ |
| Method-level authorization (`@PreAuthorize`) | ❌ | ✅ |
| Framework independence | ✅ (Domain libraries) | ❌ |
| Dependency Injection | ✅ | ✅ |
| Clean Architecture | ✅ | Partial |

---

# License

MIT License.