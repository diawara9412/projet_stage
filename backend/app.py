from fastapi import FastAPI

from api.routes import datasets, evaluation, health, rules, simulation

app = FastAPI(title="LLM Security Chain Pipeline", version="1.0.0")

app.include_router(health.router, prefix="/api/health", tags=["health"])
app.include_router(datasets.router, prefix="/api/datasets", tags=["datasets"])
app.include_router(simulation.router, prefix="/api/simulation", tags=["simulation"])
app.include_router(rules.router, prefix="/api/rules", tags=["rules"])
app.include_router(evaluation.router, prefix="/api/evaluation", tags=["evaluation"])


@app.get("/")
def root() -> dict:
    return {"message": "LLM security pipeline is running"}
