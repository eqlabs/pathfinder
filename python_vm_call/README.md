# Development

Setup development environment by creating a virtual environment and entering it:

```bash
$ python3 -m venv .venv
$ source .venv/bin/activate
```

Then install tools:

```bash
$ PIP_REQUIRE_VIRTUALENV=true pip install --upgrade pip
```

Then install development tools:

```
$ PIP_REQUIRE_VIRTUALENV=true pip install -r requirements-dev.txt
```

