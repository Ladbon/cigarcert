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

## Notes

- Ensure the API project is running if integration tests depend on it.
- Keep tests independent and repeatable.

## License

This project is licensed under the MIT License.

