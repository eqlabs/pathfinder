.PHONY: sync

# Detect Python command - try python3 first, then python
PYTHON := $(shell command -v python3 2> /dev/null || command -v python 2> /dev/null)

# Check if Python was found
ifeq ($(PYTHON),)
    $(error "Python not found. Please install Python 3.x")
endif

sync:
	$(PYTHON) scripts/sync_protos.py
	$(PYTHON) scripts/generate_bindings.py