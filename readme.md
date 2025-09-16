# CigarCertifierAPI

CigarCertifierAPI is a web API built with **ASP.NET Core (.NET 9)** and **C#**. It provides endpoints for managing cigars, manufacturers, and certifications, with solid authentication including **JWT** and optional **Two-Factor Authentication (2FA)** via **TOTP** (QR code setup supported).

---

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
  - [Clone the Repository](#clone-the-repository)
  - [Configure the Application](#configure-the-application)
  - [Keys & Certificates](#keys--certificates)
  - [Build & Run](#build--run)
  - [API Documentation](#api-documentation)
- [Usage](#usage)
  - [Authentication](#authentication)
  - [Password Management](#password-management)
  - [Protected Resource Example](#protected-resource-example)
- [Configuration Details](#configuration-details)
- [Logging](#logging)
- [Security Considerations](#security-considerations)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **User Authentication**: Secure registration and login using JWTs; optional 2FA.
- **Password Management**: BCrypt hashing, reset flow, and validation.
- **Cigar Management**: CRUD for cigars, manufacturers, and certifications.
- **Two-Factor Authentication (2FA)**: TOTP support with QR code generation.
- **Security Enhancements**:
  - JWT validation and blacklisting.
  - Middleware for security headers.
  - Rate limiting on sensitive endpoints.
- **Logging**: Structured logging via `LoggerService`.
- **API Documentation**: Built-in Swagger / OpenAPI.

---

## Prerequisites

- .NET 9 SDK
- Visual Studio 2022 (or VS Code + C# Dev Kit)
- SQL Server (or compatible SQL database)
- SendGrid API Key (for email delivery)

---

## Getting Started

### Clone the Repository

```bash
git clone https://github.com/yourusername/cigar-certifier-api.git
cd cigar-certifier-api
```

### Configure the Application

1) **Environment Variables**

Create a `.env` file in the project root **or** set these as environment variables / User Secrets:

```env
# Database
ConnectionStrings__DefaultConnection=Server=YOUR_SQL_HOST;Database=CigarCertifier;User Id=...;Password=...;TrustServerCertificate=True;

# Auth
JWT_SECRET=your-strong-32char-min-secret
SA_PASSWORD=your-local-sa-password

# Email (SendGrid)
SENDGRID_API_KEY=SG.xxxxx
EmailSettings__SenderEmail=youremail@example.com
EmailSettings__SenderName=Your Name
```

2) **App Settings**

Ensure your `appsettings.json` contains the relevant sections (values can be overridden by env vars):

```json
{
  "Jwt": {
    "Issuer": "CigarCertifierAPI",
    "Audience": "CigarCertifierAPI",
    "ExpiryMinutes": 30
  },
  "EmailSettings": {
    "SenderEmail": "youremail@example.com",
    "SenderName": "Your Name"
  }
}
```

> Tip (Windows dev): you can also use .NET User Secrets for local dev:
>
> ```bash
> dotnet user-secrets set "JWT_SECRET" "your-strong-32char-min-secret" --project CigarCertifierAPI
> ```

### Keys & Certificates

#### JWT Signing Key

Generate a strong random key (min 32 chars):

```bash
openssl rand -base64 32
```

#### HTTPS Development Certificate

```bash
dotnet dev-certs https --clean
dotnet dev-certs https --trust
```

#### Production SSL Certificates

Use a valid certificate from a trusted CA (e.g., Let’s Encrypt). Configure in your hosting environment or (for direct Kestrel hosting):

```bash
dotnet run --urls="https://+:443;http://+:80"   --certificatePath="/path/to/certificate.pfx"   --certificatePassword="your-certificate-password"
```

### Build & Run

```bash
# Restore packages
dotnet restore

# Apply EF Core migrations (ensure your connection string is set)
dotnet ef database update

# Run the API
dotnet run --project CigarCertifierAPI
```

By default, the API will be available at:

- https://localhost:5001  
- http://localhost:5000

### API Documentation

Open Swagger UI:

- https://localhost:5001/swagger

---

## Usage

### Authentication

- `POST /api/auth/register` — Register a new user.
- `POST /api/auth/login` — Log in and receive a JWT.
- `DELETE /api/auth/logout` — Log out and invalidate the current token.
- `PATCH /api/auth/setup-2fa` — Initiate 2FA setup (requires auth; returns provisioning info/QR).
- `POST /api/auth/activate-2fa` — Activate 2FA with the provided TOTP code.
- `GET /api/auth/2fa-status` — Check if 2FA is enabled.

### Password Management

- `POST /api/auth/request-password-reset` — Send password reset email.
- `POST /api/auth/reset-password` — Reset password using the received token.

### Protected Resource Example

- `GET /api/auth/protected` — Example secured endpoint (requires valid JWT).

---

## Configuration Details

- **JWT Settings**: `JWT_SECRET` MUST be at least 32 characters. Set via env vars or secrets.
- **Email Settings**: Configure `EmailSettings` or env vars. Uses SendGrid for outbound mail.

---

## Logging

The API uses the built-in .NET logging abstractions with a `LoggerService` wrapper for structured, centralized logs. Configure log levels in `appsettings.json` under `Logging`.

---

## Security Considerations

- **Password Security**: Passwords hashed with **BCrypt** before storage.
- **2FA**: Optional TOTP-based second factor to protect accounts.
- **Token Management**: JWT validation enforced; blacklisted tokens blocked from reuse.
- **Rate Limiting**: Applied to sensitive endpoints to mitigate brute-force attacks.
- **Security Headers**: Middleware adds recommended HTTP security headers.

---

## Testing

See the test project guide here: [CigarCertifierAPI.Tests/README.md](./CigarCertifierAPI.Tests/README.md)

---

## Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch
3. Commit with clear messages
4. Open a pull request describing your changes

Please include appropriate tests and documentation for new code.

---

## License

This project is licensed under the **MIT License**.
