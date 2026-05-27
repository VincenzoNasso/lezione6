

import os
import time
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

import httpx
import joblib
import numpy as np
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
from pydantic import BaseModel
from tenacity import retry, stop_after_attempt, wait_exponential


MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
ES_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
ES_INDEX = "traffic-logs"

FEATURE_NAMES = [
    "packet_size",
    "request_rate",
    "connection_duration",
    "payload_entropy",
    "header_count",
    "error_rate",
    "unique_endpoints",
    "byte_variance",
]


inference_latency = Histogram(
    "inference_latency_seconds",
    "Latency of /predict endpoint",
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
)
predictions_total = Counter(
    "predictions_total",
    "Total predictions",
    ["result"],
)
model_confidence_gauge = Gauge(
    "model_confidence",
    "Running average model confidence",
)


_conf_sum = 0.0
_conf_count = 0

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
model = None
http_client: Optional[httpx.AsyncClient] = None


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global model, http_client
    # load model
    model = joblib.load(MODEL_PATH)
    print(f"[inference_api] Modello caricato da {MODEL_PATH}", flush=True)
    http_client = httpx.AsyncClient(timeout=5.0)
    yield
    await http_client.aclose()


app = FastAPI(title="AI vs Cyber Threats — Inference API", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class TrafficFeatures(BaseModel):
    packet_size: float
    request_rate: float
    connection_duration: float
    payload_entropy: float
    header_count: float
    error_rate: float
    unique_endpoints: float
    byte_variance: float


class PredictionResponse(BaseModel):
    label: int
    label_str: str
    confidence: float
    timestamp: str



@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=0.5, min=0.1, max=2))
async def _send_to_es(doc: dict):
    resp = await http_client.post(f"{ES_URL}/{ES_INDEX}/_doc", json=doc)
    resp.raise_for_status()


async def send_to_es_background(doc: dict):
    try:
        await _send_to_es(doc)
    except Exception as exc:
        print(f"[inference_api] ES send error: {exc}", flush=True)


@app.get("/health")
async def health():
    return {"status": "ok", "model_loaded": model is not None}


@app.post("/predict", response_model=PredictionResponse)
async def predict(features: TrafficFeatures, request: Request):
    global _conf_sum, _conf_count

    t0 = time.perf_counter()

    X = np.array([[
        features.packet_size,
        features.request_rate,
        features.connection_duration,
        features.payload_entropy,
        features.header_count,
        features.error_rate,
        features.unique_endpoints,
        features.byte_variance,
    ]])

    proba = model.predict_proba(X)[0]
    label = int(np.argmax(proba))
    confidence = float(proba[label])
    label_str = "malicious" if label == 1 else "benign"

    elapsed = time.perf_counter() - t0
    processing_ms = elapsed * 1000.0

    
    inference_latency.observe(elapsed)
    predictions_total.labels(result=label_str).inc()
    _conf_sum += confidence
    _conf_count += 1
    model_confidence_gauge.set(_conf_sum / _conf_count)

    ts = datetime.now(timezone.utc).isoformat()

    
    doc = {
        "@timestamp": ts,
        "features": features.model_dump(),
        "prediction": label,
        "prediction_label": label_str,
        "confidence": confidence,
        "source_ip": request.client.host if request.client else "unknown",
        "processing_ms": round(processing_ms, 2),
    }
    asyncio.create_task(send_to_es_background(doc))

    return PredictionResponse(
        label=label,
        label_str=label_str,
        confidence=round(confidence, 4),
        timestamp=ts,
    )


@app.get("/metrics")
async def metrics():
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)
