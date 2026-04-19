from fastapi import APIRouter

from datasets.dataset_manager import DatasetManager

router = APIRouter()
manager = DatasetManager()


@router.get("/")
def list_datasets() -> dict:
    return manager.list_datasets()
