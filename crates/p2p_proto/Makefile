.PHONY: sync

# Detect Python command - try python3 first, then python
PYTHON := $(shell command -v python3 2> /dev/null || command -v python 2> /dev/null)

# Check if Python was found
ifeq ($(PYTHON),)
    $(error "Python not found. Please install Python 3.10+")
endif

# Check Python version
PYTHON_VERSION := $(shell $(PYTHON) -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)
PYTHON_VERSION_CHECK := $(shell $(PYTHON) -c "import sys; exit(0 if sys.version_info >= (3, 10) else 1)" 2>/dev/null && echo "ok" || echo "fail")

sync:
	@echo "Using Python: $$($(PYTHON) --version)"
	@if [ "$(PYTHON_VERSION_CHECK)" != "ok" ]; then \
		echo "❌ Error: Python 3.10+ required, but found $(PYTHON_VERSION)"; \
		echo "   Please upgrade your Python installation."; \
		echo "   Your current version: $$($(PYTHON) --version)"; \
		exit 1; \
	fi
	@echo "✅ Python version check passed"
	$(PYTHON) scripts/sync_protos.py
	$(PYTHON) scripts/generate_bindings.py
