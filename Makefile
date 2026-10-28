.PHONY: install test check
install:
	pip install -r requirements-dev.txt
test:
	python -m pytest
check:
	scripts/check.sh
