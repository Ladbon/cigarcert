# CigarCertifierAPI.Tests

This project contains unit and integration tests for the CigarCertifierAPI.

## Prerequisites

- **.NET 9 SDK**
- **xUnit.net**: Used for testing.
- **Moq**: Used for mocking dependencies.

## Running Tests

Navigate to the test project directory:

cd CigarCertifierAPI.Tests

Run all tests using the .NET CLI:

dotnet test

## Test Structure

- **Unit Tests**: Tests that focus on individual components.
- **Integration Tests**: Tests that cover interactions between components and middleware.

## Adding Tests

1. Create a new test class in the appropriate folder.
2. Use `[Fact]` for unit tests or `[Theory]` with test data.
3. Utilize `Moq` to mock dependencies as needed.

## Configuration for Tests
Test Settings
Create a testsettings.json file:

{
  "ConnectionStrings": {
    "TestConnection": "Data Source=:memory:"
  },
  "JwtSettings": {
    "Issuer": "TestIssuer",
    "Audience": "TestAudience",
    "ExpiryInMinutes": 10,
    "SecretKey": "test-secret-key-for-development-only"
  }
}

## Using Test User Secrets
For sensitive test data:
dotnet user-secrets set "TestApiKey" "your-test-api-key" --project CigarCertifierAPI.Tests

## Notes

Ensure the API project is running if integration tests depend on it.
Keep tests independent and repeatable.
Do not commit test credentials to source control.

## License

This project is licensed under the MIT License.

