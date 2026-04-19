from pathlib import Path

DATA_ROOT = Path(__file__).resolve().parent.parent / "data"
DATASET_PATHS = {
    "cic_ids2017": DATA_ROOT / "cic_ids2017",
    "cse_cic_ids2018": DATA_ROOT / "cse_cic_ids2018",
    "unsw_nb15": DATA_ROOT / "unsw_nb15",
    "simulations": DATA_ROOT / "simulations",
}
