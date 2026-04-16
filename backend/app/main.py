from __future__ import annotations

import json
import uuid
from pathlib import Path

import yaml
from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.db import get_run, get_upload, init_db, insert_run, insert_upload, now_iso, update_upload
from app.llm_providers.providers import get_provider_registry
from app.services.parsers import parse_upload
from app.services.runs import execute_and_store
from app.services.scenario import build_scenario

app = FastAPI(title=settings.app_name)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[item.strip() for item in settings.cors_origins.split(",") if item.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    init_db()
    settings.data_path.mkdir(parents=True, exist_ok=True)


class RunRequest(BaseModel):
    upload_id: str
    models: list[str] = Field(default_factory=lambda: ["llama_ollama"])
    repeats: int = 1


@app.post("/api/uploads")
async def upload(file: UploadFile = File(...)):
    suffix = Path(file.filename or "").suffix.lower()
    if suffix in {".pcap", ".pcapng"}:
        file_type = "pcap"
    elif suffix == ".json":
        file_type = "netflow_json"
    elif suffix == ".csv":
        file_type = "netflow_csv"
    else:
        raise HTTPException(status_code=400, detail="Unsupported file type. Use pcap, csv, or json")

    upload_id = str(uuid.uuid4())
    upload_dir = settings.data_path / "uploads" / upload_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    target = upload_dir / (file.filename or f"upload{suffix}")
    content = await file.read()
    target.write_bytes(content)

    record = {
        "id": upload_id,
        "filename": file.filename or target.name,
        "file_type": file_type,
        "path": str(target),
        "status": "uploaded",
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "parsed_artifact": None,
        "scenario_artifact": None,
    }
    insert_upload(record)
    return {"upload_id": upload_id, "file_type": file_type, "filename": record["filename"]}


@app.post("/api/uploads/{upload_id}/parse")
def parse(upload_id: str):
    upload_record = get_upload(upload_id)
    if not upload_record:
        raise HTTPException(status_code=404, detail="Upload not found")

    file_path = Path(upload_record["path"])
    flows = parse_upload(file_path, upload_record["file_type"])

    parsed_path = settings.data_path / "uploads" / upload_id / "parsed_flows.json"
    parsed_path.write_text(json.dumps(flows, indent=2), encoding="utf-8")

    update_upload(upload_id, status="parsed", parsed_artifact=str(parsed_path))
    return {"upload_id": upload_id, "flows_count": len(flows), "parsed_artifact": str(parsed_path)}


@app.post("/api/uploads/{upload_id}/scenario")
def scenario(upload_id: str):
    upload_record = get_upload(upload_id)
    if not upload_record:
        raise HTTPException(status_code=404, detail="Upload not found")

    parsed_artifact = upload_record.get("parsed_artifact")
    if not parsed_artifact:
        raise HTTPException(status_code=400, detail="Upload must be parsed first")

    flows = json.loads(Path(parsed_artifact).read_text(encoding="utf-8"))
    scenario_data = build_scenario(flows)
    scenario_path = settings.data_path / "uploads" / upload_id / "scenario.yaml"
    scenario_path.write_text(yaml.safe_dump(scenario_data, sort_keys=False), encoding="utf-8")
    update_upload(upload_id, status="scenario_ready", scenario_artifact=str(scenario_path))

    return {"upload_id": upload_id, "scenario_artifact": str(scenario_path), "scenario": scenario_data}


@app.get("/api/models")
def models():
    registry = get_provider_registry()
    return {
        "models": [
            {
                "name": name,
                "available": provider.available(),
            }
            for name, provider in registry.items()
        ]
    }


@app.post("/api/runs")
async def runs(payload: RunRequest, background_tasks: BackgroundTasks):
    upload_record = get_upload(payload.upload_id)
    if not upload_record:
        raise HTTPException(status_code=404, detail="Upload not found")
    if not upload_record.get("scenario_artifact"):
        raise HTTPException(status_code=400, detail="Scenario must be generated before running benchmark")

    run_id = str(uuid.uuid4())
    run_dir = settings.data_path / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    scenario_data = yaml.safe_load(Path(upload_record["scenario_artifact"]).read_text(encoding="utf-8"))

    insert_run(
        {
            "id": run_id,
            "upload_id": payload.upload_id,
            "models": payload.models,
            "repeats": payload.repeats,
            "status": "running",
            "created_at": now_iso(),
            "updated_at": now_iso(),
            "run_dir": str(run_dir),
            "result_artifact": None,
            "metrics_json": None,
            "metrics_csv": None,
        }
    )

    background_tasks.add_task(execute_and_store, run_id, run_dir, scenario_data, payload.models, payload.repeats)
    return {"run_id": run_id, "status": "running"}


@app.get("/api/runs/{run_id}")
def run_detail(run_id: str):
    run_record = get_run(run_id)
    if not run_record:
        raise HTTPException(status_code=404, detail="Run not found")

    response = {
        "run_id": run_record["id"],
        "status": run_record["status"],
        "upload_id": run_record["upload_id"],
        "models": run_record["models"],
        "repeats": run_record["repeats"],
    }

    if run_record.get("result_artifact"):
        response["result"] = json.loads(run_record["result_artifact"])
    return response


@app.get("/api/runs/{run_id}/export.zip")
def run_export(run_id: str):
    run_record = get_run(run_id)
    if not run_record:
        raise HTTPException(status_code=404, detail="Run not found")
    if run_record["status"] != "completed":
        raise HTTPException(status_code=400, detail="Run not completed")

    result = json.loads(run_record["result_artifact"])
    export_path = result.get("export")
    if not export_path or not Path(export_path).exists():
        raise HTTPException(status_code=404, detail="Export not found")

    return FileResponse(path=export_path, media_type="application/zip", filename=f"run-{run_id}-export.zip")
