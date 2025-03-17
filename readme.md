# CigarCertifierAPI

CigarCertifierAPI is a web API developed using ASP.NET Core (.NET 9) and C#. It provides functionalities for managing cigar certifications, manufacturers, 
and includes robust authentication mechanisms with support for two-factor authentication (2FA) using Time-based One-Time Passwords (TOTP).

## Features

�	User Authentication: Secure user registration and login using JWT tokens with optional 2FA.
�	Password Management: Secure password hashing, reset functionality, and validations.
�	Cigar Management: CRUD operations for cigars, manufacturers, and certifications.
�	Two-Factor Authentication (2FA): Enhances account security via TOTP, with QR code generation for easy setup.
�	Security Enhancements:
�	JWT token validation and blacklisting.
�	Middleware for adding security-related HTTP headers.
�	Rate limiting on sensitive endpoints to prevent brute-force attacks.
�	Logging: Structured and centralized logging using LoggerService.
�	API Documentation: Integrated Swagger/OpenAPI support for easy API exploration.

## Prerequisites

�	.NET 9 SDK
�	Visual Studio 2022 or later
�	SQL Server (or any compatible SQL database)
�	SendGrid API Key (for sending emails)

## Getting Started

### Clone the Repository

git clone https://github.com/yourusername/cigar-certifier-api.git
cd cigar-certifier-api

### Configure the Application

1.	Environment Variables:
Create a .env file in the project root or set the following environment variables:
SA_PASSWORD=
JWT_SECRET=
ConnectionStrings__DefaultConnection=Server=
SENDGRID_API_KEY=
EmailSettings__SenderEmail=
EmailSettings__SenderName=
Ensure the appsettings.json file has the correct configuration for JWT and email settings:
 
	   "Jwt": {
     "Issuer": "CigarCertifierAPI",
     "Audience": "CigarCertifierAPI",
     "ExpiryMinutes": 30
   },
   "EmailSettings": {
     "SenderEmail": "youremail@example.com",
     "SenderName": "Your Name"
   }
    
## 5. Keys and Certificates Setup Instructions

## Setting Up Keys and Certificates

### JWT Signing Key
  
1. Generate a strong random key (at least 32 characters)
   ���bash```
   openssl rand -base64 32

HTTPS Development Certificate
dotnet dev-certs https --clean
dotnet dev-certs https --trust

Production SSL Certificates
For production, you should use a valid SSL certificate from a trusted Certificate Authority.

Purchase or obtain a free certificate (e.g., Let's Encrypt)
Configure in your hosting environment or:
Production SSL Certificates

For production, you should use a valid SSL certificate from a trusted Certificate Authority.
# For Kestrel direct hosting
dotnet run --urls="https://+:443;http://+:80" --certificatePath="/path/to/certificate.pfx" --certificatePassword="your-certificate-password"


### Build and Run the Application

1. Restore dependencies: dotnet restore
2. Apply migrations: dotnet ef database update
3. Run the application: dotnet run --project CigarCertifierAPI 

The API should now be running at https://localhost:5001 or http://localhost:5000.

### Access the API Documentation

Navigate to https://localhost:5001/swagger to access the Swagger UI and explore the API endpoints.

## Usage

Endpoints Overview

	Authentication:
�	POST /api/auth/register: Register a new user.
�	POST /api/auth/login: Log in and receive a JWT token.
�	DELETE /api/auth/logout: Log out and invalidate the current token.
�	PATCH /api/auth/setup-2fa: Initiate 2FA setup (requires authentication).
�	POST /api/auth/activate-2fa: Activate 2FA with the provided token.
�	GET /api/auth/2fa-status: Check if 2FA is enabled.

	Password Management:
�	POST /api/auth/request-password-reset: Request a password reset email.
�	POST /api/auth/reset-password: Reset the password using the token provided.

	Protected Resource Example:
�	GET /api/auth/protected: Access a protected endpoint (requires authentication).

### Configuration Details

�	JWT Settings:
Ensure that the JWT_SECRET environment variable or configuration setting is set and is at least 32 characters long for security.
�	Email Settings:
Update the EmailSettings section in appsettings.json or use environment variables to configure the sender's email and name. The application uses SendGrid for sending emails.

### Logging

The application uses the built-in logging framework with LoggerService to log important events and errors. Logs can be configured in appsettings.json under the Logging section.

### Security Considerations
�	Password Security: Passwords are hashed using BCrypt before storage.
�	2FA: Users can enable 2FA to add an extra layer of security.
�	Token Management: Tokens are validated, and blacklisted tokens are stored to prevent reuse.
�	Rate Limiting: Sensitive endpoints have rate limiting to prevent abuse.

## Testing

Instructions for running tests are available in the [CigarCertifierAPI.Tests README](./CigarCertifierAPI.Tests/README.md).

## Contributing

Contributions are welcome! To contribute:
1.	Fork the repository.
2.	Create a new branch for your feature or bug fix.
3.	Commit your changes with clear commit messages.
4.	Open a pull request describing your changes.
Please ensure all new code includes appropriate tests and documentation.


## License

This project is licensed under the MIT License.