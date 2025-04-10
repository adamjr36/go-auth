# Auth Module Tests

This directory contains tests for the auth module. The tests cover various functionalities including initialization, password handling, user authentication, token validation, token refresh, and edge cases.

## Test Structure

Tests are organized into separate files, each focusing on a specific aspect of the auth module:

1. `test_001_init_test.go` - Tests for initializing the auth module
2. `test_002_passwords_test.go` - Tests for password hashing and comparison
3. `test_003_signup_test.go` - Tests for user sign-up functionality
4. `test_004_signin_test.go` - Tests for user sign-in functionality
5. `test_005_token_validation_test.go` - Tests for JWT token validation
6. `test_006_token_refresh_test.go` - Tests for token refresh functionality
7. `test_007_signout_delete_test.go` - Tests for sign-out and user deletion
8. `test_008_edge_cases_test.go` - Tests for edge cases and error handling

## Running Tests

The project includes a Makefile with various targets to help run tests and analyze test coverage.

### Basic Test Commands

From the project root directory, run:

```bash
# Run all tests
make test

# Run tests with verbose output
make test-verbose

# Run tests with a detailed summary of passed/failed tests
make test-summary

# Run tests and generate a coverage report
make cover

# Run tests and generate an HTML coverage report
make cover-html

# Run tests with race detection
make race

# Run benchmarks
make benchmark
```

### Running Specific Tests

To run tests matching a specific pattern:

```bash
make test-pattern PATTERN="TestSignIn"
```

Replace `TestSignIn` with any test name or pattern you want to match.

### Cleaning Up

To clean up generated files:

```bash
make clean
```

## Test Coverage

The test suite aims to provide comprehensive coverage of the auth module. Test coverage can be viewed with:

```bash
make cover
```

Or generate an HTML coverage report with:

```bash
make cover-html
```

## Adding New Tests

When adding new tests:

1. Follow the naming convention: `test_0xx_description_test.go`
2. Keep each test file focused on a specific aspect of the auth module
3. Keep test files under 200 lines of code
4. Ensure your tests include assertions for both success and failure cases
5. Consider edge cases in your test scenarios 