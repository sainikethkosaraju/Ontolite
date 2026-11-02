from pathlib import Path

import pytest

from ontolite.ingest.sec_loader import load_sec
from ontolite.runtime import Ontolite


def _patch_tiktoken_if_offline():
    """Inspect's token counter downloads a vocabulary on first use; some sandboxes block that. When (and
    only when) the download fails, a whitespace tokenizer is patched in: token COUNTS only."""
    try:
        import tiktoken
    except ImportError:
        return
    try:
        tiktoken.get_encoding("o200k_base")
        return
    except Exception:
        pass

    class _E:
        def encode(self, t, **k): return t.split()
        def decode(self, t, **k): return " ".join(t)
    tiktoken.get_encoding = lambda *a, **k: _E()
    tiktoken.encoding_for_model = lambda *a, **k: _E()


_patch_tiktoken_if_offline()

DEMO = Path(__file__).parent.parent / "demo" / "sec"
BACKENDS = ["sqlite", "duckdb"]


def build(backend="sqlite"):
    r = Ontolite.open(DEMO / "schema.yaml", DEMO / "principals.yaml", backend=backend)
    load_sec(r.schema, r.store, DEMO / "sample", DEMO / "mappings.yaml")
    return r


@pytest.fixture
def rt():
    return build("sqlite")


@pytest.fixture(params=BACKENDS)
def rt_any(request):
    pytest.importorskip("duckdb") if request.param == "duckdb" else None
    return build(request.param)
