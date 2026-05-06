from pydantic import BaseModel
from typing import Dict, List, Union


class PredictionRequest(BaseModel):
    features: Dict[str, Union[int, float]]


class BatchPredictionRequest(BaseModel):
    records: List[Dict[str, Union[int, float]]]