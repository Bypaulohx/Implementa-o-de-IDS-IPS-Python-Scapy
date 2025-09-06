import time
import logging
from pathlib import Path

logger = logging.getLogger("ids")

def ensure_dir(path):
    p = Path(path)
    if not p.parent.exists():
        p.parent.mkdir(parents=True, exist_ok=True)

def now_ts():
    return time.time()
