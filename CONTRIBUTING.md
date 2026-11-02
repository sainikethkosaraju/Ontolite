# Contributing
`pip install -e .[dev]`; `pytest && ruff check . && pyright` must pass. Anything touching permissions, actions, audit or the store needs a test; the leakage suite and the fuzzer must stay green on both backends; benchmark changes must keep `tests/test_bench.py` (reference 40/40, null 6/40, every mutant detected) passing.
