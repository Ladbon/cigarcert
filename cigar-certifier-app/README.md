# Cigar Certifier Application

A modern Angular-based web application for cigar certification and authentication with enterprise-grade security features.

## Features

### Authentication & Security
- 🔒 Multi-factor authentication with TOTP support
- 🔑 Secure JWT-based authentication with HttpOnly cookies
- 📱 Mobile-friendly authentication flows
- 🛡️ Protection against brute force attacks with rate limiting
- ⏱️ Intelligent session management with idle timeout warnings
- 🔄 Automatic token refresh for seamless user experience

### User Management
- 📝 User registration with email verification
- 🔐 Secure password reset workflows
- 👤 Self-service profile management
- 📧 Email notifications for security events

## Development Setup

### Prerequisites
- Node.js (v22.11+)
- Angular CLI (v19+)
- A running instance of the Cigar Certifier API

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/ladbon/cigar-certifier-app.git
   cd cigar-certifier-app
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure environment variables:
   - Create a `environment.development.ts` file in the `src/environments/` directory
   - Set the API URL in your environment file:
     ```typescript
     export const environment = {
       production: false,
       apiUrl: 'https://localhost:5001/api/auth'
     };
     ```

4. Start the development server:
   ```bash
   ng serve
   ```

5. Navigate to `https://localhost:4200/` in your browser

## Architecture

The application follows a component-based architecture with reactive state management:

- **Core Services** - Authentication, token management, and HTTP interceptors
- **Feature Modules** - Lazy-loaded modules for different application features
- **Shared Components** - Reusable UI components and directives
- **Guards & Interceptors** - Route protection and HTTP request/response handling

## Testing

### Unit Tests
```bash
ng test
```

### End-to-End Tests
```bash
ng e2e
```

## Building for Production

```bash
ng build --configuration production
```

This creates optimized production files in the dist directory, ready for deployment.

## Security Practices

- ✅ No sensitive data stored in localStorage
- ✅ CSRF protection via HttpOnly cookies
- ✅ Protection against session hijacking
- ✅ Automatic session termination on password reset
- ✅ Comprehensive error handling with user-friendly messages
- ✅ Progressive security with opt-in 2FA

## Frontend-Backend Security Integration
Token Management
HTTP interceptors attach authentication tokens to requests
Automatic token refresh occurs before expiration
Auth guard prevents access to protected routes
Environment Configuration
Production configuration removes debug information and optimizes security:

// environment.prod.ts example
export const environment = {
  production: true,
  apiUrl: '/api',
  tokenRefreshInterval: 240000, // 4 minutes
  sessionTimeout: 1800000 // 30 minutes
};

## # Updated Cigar Certifier App README

## Security Authentication System

The Cigar Certifier Application is a modern, secure authentication platform built with Angular and ASP.NET Core, featuring enterprise-grade security controls.

## Security Features

### Authentication
- **JWT-based Authentication** - Securely stored in HttpOnly cookies
- **Multi-Factor Authentication** - TOTP implementation with QR code support
- **Session Management** - Idle timeout detection with user warnings
- **Advanced Token Controls**
  - Token blacklisting and invalidation
  - Automatic session termination on password reset
  - Active session tracking across devices
  
### Security Protections
- **XSS Prevention** - HttpOnly cookies prevent token theft via JavaScript
- **Input Sanitization** - DomSanitizer for proper HTML encoding
- **Rate Limiting** - Prevents brute force attempts
- **CSRF Protection** - SameSite cookie configuration

## Setup Instructions

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/cigar-certifier-app.git
   cd cigar-certifier-app
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Important Security Update**
   Fix the vite security vulnerability (CVE-2025-XYZ):
   ```bash
   npm update @angular-devkit/build-angular
   ```
   Or explicitly update vite:
   ```bash
   npm install vite@latest
   ```

4. **Run development server**
   ```bash
   ng serve
   ```

## Architecture

- **Frontend**: Angular 19 with reactive forms and JWT authentication
- **Backend**: ASP.NET Core with Entity Framework Core
- **Security**: Multiple layers of defense with token validation
- **Testing**: Comprehensive test suite with mocked HTTP endpoints

## Development Notes

- Run backend before testing authentication flows
- Use Chrome DevTools to inspect Authentication cookies
- For unit tests, no backend is needed as requests are mocked

## Testing

```bash
ng test                # Run all tests with mocked backend
ng test --include=**/auth.service.spec.ts  # Test auth service only
```

## Best Practices Implemented

- **DRY Principle**: Centralized authentication logic
- **KISS Principle**: Simple, focused components
- **Security by Design**: Multiple defense layers
- **Responsive UI**: Mobile-friendly authentication

## License

This project is licensed under the MIT License.