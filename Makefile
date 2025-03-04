.DEFAULT_GOAL := help
SHELL := /usr/bin/env bash

# Process all recipes in the current file looking for targets and comments with two hashtags
# parsing them into nicely formatted table
.PHONY: help
help:
	@grep -E '(^[/\.a-zA-Z_\-]+:.*?##.*$$)|(^##)' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}' | sed -e 's/\[32m##/[33m/' && echo ""

##
## Linting
.PHONY: check flake pylint
check: lint flake  ## Run code checks with both pylint and flake8
lint:  ## Check code with pylint
	-pylint ./bit_vault_warden_client ./tests/
flake:  ## Check code with flake8
	-@flake8 -v

##
## Testing
.PHONY: test test-with-coverage
test:  ## Run unit tests
	@python -m pytest ./tests
test-with-coverage:  ## Run unit tests with coverage
	@rm -rf ./htmlcov
	@rm -f ./.coverage
	@PYTHONPATH=. pytest --cov-report html --cov=bit_vault_warden_client
