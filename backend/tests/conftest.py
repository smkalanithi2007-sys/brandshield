import os
import sys
import tempfile
from pathlib import Path

from sqlalchemy.engine import URL

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

test_database = Path(tempfile.gettempdir()) / "brandshield-live-tests.db"
test_database.unlink(missing_ok=True)
os.environ["DATABASE_URL"] = URL.create(
    "sqlite", database=str(test_database)
).render_as_string(hide_password=False)
os.environ["JWT_SECRET_KEY"] = "test-only-secret-not-used-outside-tests-012345"
os.environ["SCHEDULE_POLL_SECONDS"] = "3600"
os.environ["SCHEDULE_BATCH_SIZE"] = "1"
