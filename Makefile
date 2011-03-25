all: test
test:
	@echo running tests
	@phpunit --configuration tests/phpunit.xml

.PHONY: all test
