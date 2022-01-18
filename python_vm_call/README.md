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

Finally install the only real dependency, which cannot currently be managed by lock files:

```
$ PIP_REQUIRE_VIRTUALENV=true pip install cairo-lang==0.6.2
```

## Testing

Inside the virtual environment, in the same directory as this README, after installing all of the dependencies:

```
$ pytest
```
