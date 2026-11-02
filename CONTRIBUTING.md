# Contributing
`pip install -e .[dev]`; `pytest && ruff check . && pyright` must pass. Any change touching permissions, actions or audit needs a test, and the leakage suite must stay at zero leaks.
