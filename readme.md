# CigarCertifierAPI

CigarCertifierAPI is a .NET 9 Web API that manages cigar certifications, manufacturers, and authentication with two-factor authentication (2FA) support.

## Features

- **User Authentication**: Secure login with JWT tokens and optional 2FA using TOTP.
- **Password Reset**: Request and reset passwords securely.
- **Cigar Management**: CRUD operations for cigars and certifications.
- **Manufacturer Management**: Manage manufacturer details.
- **Logging**: Structured logging with `LoggerService`.
- **Swagger/OpenAPI**: Auto-generated API documentation.

## Prerequisites

- **.NET 9 SDK**
- **Visual Studio 2022** or later
- **SQL Server** or another compatible database

## Getting Started

### Clone the Repository

git clone https://github.com/yourusername/cigar-certifier-api.git cd cigar-certifier-api

### Build the Project

dotnet build

### Database Setup

Configure the connection string in `appsettings.json`:

"ConnectionStrings": { "DefaultConnection": "YourDatabaseConnectionString" }

### Apply migrations to set up the database schema:

dotnet ef database update


### Run the Application

dotnet run --project CigarCertifierAPI


Navigate to `https://localhost:{port}/swagger` to access the Swagger UI.

## Configuration

- **JWT Settings**: Configure issuer, audience, and secret key in `appsettings.json`.
- **Logging**: Adjust logging levels and outputs as needed.

## Usage

- **Registration**: `/api/auth/register`
- **Login**: `/api/auth/login`
- **2FA Setup**: `/api/auth/setup-2fa`
- **Protected Endpoint**: `/api/auth/protected`

Refer to the Swagger UI for detailed API documentation.

## Testing

Instructions for running tests are available in the [CigarCertifierAPI.Tests README](./CigarCertifierAPI.Tests/README.md).

## Contributing

Contributions are welcome. Please create issues or pull requests for any changes.

## License

This project is licensed under the MIT License.