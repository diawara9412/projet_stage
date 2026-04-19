from pathlib import Path

from config.dataset_config import DATASET_PATHS


class DatasetManager:
    def __init__(self) -> None:
        for path in DATASET_PATHS.values():
            Path(path).mkdir(parents=True, exist_ok=True)

    def list_datasets(self) -> dict:
        return {
            name: {
                "path": str(path),
                "available": path.exists() and any(path.glob("*")),
            }
            for name, path in DATASET_PATHS.items()
        }

    def register_local_dataset(self, name: str, source_path: str) -> dict:
        if name not in DATASET_PATHS:
            raise ValueError(f"Unsupported dataset '{name}'")
        src = Path(source_path)
        if not src.exists():
            raise FileNotFoundError(source_path)
        dst = DATASET_PATHS[name] / src.name
        dst.write_bytes(src.read_bytes())
        return {"dataset": name, "stored_at": str(dst)}
