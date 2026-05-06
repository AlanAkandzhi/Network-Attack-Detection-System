from fastapi import FastAPI
from backend.schemas import PredictionRequest, BatchPredictionRequest
from backend.ml_service import MLService


app = FastAPI(
    title="Network Attack Detection API",
    description="API for detecting network attacks using machine learning.",
    version="1.0.0"
)

ml_service = MLService()


@app.get("/")
def home():
    return {
        "message": "Network Attack Detection API is running.",
        "status": "ok"
    }


@app.post("/predict")
def predict(request: PredictionRequest):
    result = ml_service.predict_batch([request.features])
    return result[0]


@app.post("/predict-batch")
def predict_batch(request: BatchPredictionRequest):
    results = ml_service.predict_batch(request.records)
    return {
        "total_records": len(results),
        "results": results
    }