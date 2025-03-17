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
- Node.js (v18+)
- Angular CLI (v19+)
- A running instance of the Cigar Certifier API

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cigar-certifier-app.git
   cd cigar-certifier-app
   ```
2. Install dependencies:
    npm install
3. ```markdown
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
- Node.js (v18+)
- Angular CLI (v19+)
- A running instance of the Cigar Certifier API

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cigar-certifier-app.git
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

## License

This project is licensed under the MIT License.