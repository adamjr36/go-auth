.PHONY: test test-verbose cover cover-html clean test-pattern test-summary benchmark race

# Default target
all: test

# Run tests without verbose output
test:
	@echo "Running tests..."
	@go test -count=1 ./tests -coverprofile=coverage.out
	@echo "Test summary:"
	@go tool cover -func=coverage.out | grep total | awk '{print "Coverage: " $$3}'
	@echo "Tests completed"

# Run tests with verbose output
test-verbose:
	@echo "Running tests with verbose output..."
	@go test -v -count=1 ./tests -coverprofile=coverage.out
	@echo "Test summary:"
	@go tool cover -func=coverage.out | grep total | awk '{print "Coverage: " $$3}'
	@echo "Tests completed"

# Generate coverage report
cover:
	@echo "Generating coverage report..."
	@go test -count=1 ./tests -coverprofile=coverage.out
	@go tool cover -func=coverage.out
	@echo "Coverage report generated"

# Generate HTML coverage report and open it
cover-html:
	@echo "Generating HTML coverage report..."
	@go test -count=1 ./tests -coverprofile=coverage.out
	@go tool cover -html=coverage.out -o coverage.html
	@echo "HTML coverage report generated: coverage.html"
	@if [ "$(shell uname)" = "Darwin" ]; then open coverage.html; fi

# Create test summary with detailed pass/fail statistics
test-summary:
	@echo "Running tests and generating summary..."
	@go test -v ./tests 2>&1 | tee test_output.txt
	@echo "Test Results:"
	@echo "---------------------------------"
	@PASSED=`grep -c "^--- PASS:" test_output.txt`; \
	FAILED=`grep -c "^--- FAIL:" test_output.txt`; \
	TOTAL=$$((PASSED+FAILED)); \
	echo "PASSED: $$PASSED"; \
	echo "FAILED: $$FAILED"; \
	echo "TOTAL:  $$TOTAL"; \
	echo "---------------------------------"
	@go test ./tests -coverprofile=coverage.out > /dev/null 2>&1
	@echo "Coverage: `go tool cover -func=coverage.out | grep total | awk '{print $$3}'`"
	@rm -f test_output.txt


# Clean up generated files
clean:
	@echo "Cleaning up..."
	@rm -f coverage.out coverage.html
	@echo "Cleanup complete"