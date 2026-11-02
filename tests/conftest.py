from pathlib import Path

import pytest

from ontolite.ingest.sec_loader import load_sec
from ontolite.runtime import Ontolite

DEMO = Path(__file__).parent.parent / "demo" / "sec"


@pytest.fixture
def rt():
    r = Ontolite.open(DEMO / "schema.yaml", DEMO / "principals.yaml")
    load_sec(r.schema, r.store, DEMO / "sample", DEMO / "mappings.yaml")
    return r
