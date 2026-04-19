import os
from pathlib import Path

DATASET_BASE_DIR = Path(
    os.getenv("DATASET_BASE_DIR", str(Path(__file__).resolve().parent.parent / "data"))
)
DATASET_PATHS = {
    "cic_ids2017": DATASET_BASE_DIR / "cic_ids2017",
    "cse_cic_ids2018": DATASET_BASE_DIR / "cse_cic_ids2018",
    "unsw_nb15": DATASET_BASE_DIR / "unsw_nb15",
    "simulations": DATASET_BASE_DIR / "simulations",
}
