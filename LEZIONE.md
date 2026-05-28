# AI vs Cyber Threats — Guida Completa per la Lezione

> Documento di riferimento operativo: comandi, query Grafana/Kibana, alert, e soluzione all'overfitting del modello.

---

## INDICE

1. [Architettura del sistema](#1-architettura-del-sistema)
2. [Avvio e comandi essenziali](#2-avvio-e-comandi-essenziali)
3. [Come funziona il modello ML](#3-come-funziona-il-modello-ml)
4. [Grafana — Query, Dashboard e Alert](#4-grafana--query-dashboard-e-alert)
5. [Kibana — Query, Dashboard e Alert](#5-kibana--query-dashboard-e-alert)
6. [Correlare Grafana e Kibana durante un incidente](#6-correlare-grafana-e-kibana-durante-un-incidente)
7. [Esercizio: Ridurre l'Overfitting del Modello](#7-esercizio-ridurre-loverfitting-del-modello)

---

## 1. Architettura del sistema

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Docker Network: labnet                      │
│                                                                     │
│  ┌──────────┐   POST /predict   ┌─────────────────────────────┐    │
│  │ attacker │ ────────────────► │      inference_api :8000    │    │
│  │(client)  │                   │  FastAPI + RandomForest ML  │    │
│  └──────────┘                   └──────────┬──────────────────┘    │
│                                            │                        │
│                          ┌─────────────────┼─────────────────┐     │
│                          │ fire-and-forget  │ GET /metrics    │     │
│                          ▼                 ▼                  │     │
│                  ┌──────────────┐  ┌─────────────┐           │     │
│                  │Elasticsearch │  │ Prometheus  │           │     │
│                  │   :9200      │  │   :9090     │◄──────────┘     │
│                  └──────┬───────┘  └──────┬──────┘                 │
│                         │                 │◄─── cadvisor :8080      │
│                         ▼                 ▼                         │
│                  ┌──────────────┐  ┌─────────────┐                 │
│                  │   Kibana     │  │   Grafana   │                  │
│                  │  SOC :5601   │  │  HPC :3000  │                 │
│                  └──────────────┘  └─────────────┘                 │
└─────────────────────────────────────────────────────────────────────┘
```

### Due stack di osservabilità con scopi diversi

| Stack | Tool | Granularità | Scopo |
|---|---|---|---|
| **SOC** | Elasticsearch + Kibana | Ogni singola prediction (documento JSON) | Analisi forense, drill-down sulle feature |
| **HPC** | Prometheus + Grafana | Metriche aggregate (rate, percentili) | Monitoring real-time, alert su soglie |

### Documento ES per ogni prediction

Ogni chiamata a `/predict` genera questo documento in Elasticsearch:

```json
{
  "@timestamp": "2026-05-27T10:23:45.123Z",
  "features": {
    "packet_size": 498.3,
    "request_rate": 0.12,
    "connection_duration": 112.5,
    "payload_entropy": 4.8,
    "header_count": 9.1,
    "error_rate": 0.02,
    "unique_endpoints": 1.0,
    "byte_variance": 1050.2
  },
  "prediction": 0,
  "prediction_label": "benign",
  "confidence": 0.61,
  "source_ip": "172.20.0.5",
  "processing_ms": 1.43
}
```

> **Nota:** `prediction_label: "benign"` con `confidence: 0.61` e `connection_duration: 112.5` è un **falso negativo** — il modello è incerto ma vota benign perché Slowloris lento è fuori range di training.

---

## 2. Avvio e comandi essenziali

### Avvio completo

```bash
# 1. Avvia tutti i servizi in background
docker compose up -d

# 2. Verifica che tutti i container siano healthy (attendi ~90s)
docker compose ps

# 3. Importa la dashboard Kibana (dopo che ES è healthy)
bash elastic/import_dashboard.sh
```

### URL dei servizi

| Servizio | URL | Credenziali |
|---|---|---|
| FastAPI docs | http://localhost:8000/docs | — |
| Prometheus | http://localhost:9090 | — |
| Grafana | http://localhost:3000 | admin / minilab |
| Kibana | http://localhost:5601 | — |
| cAdvisor | http://localhost:8080 | — |

### Modalità di traffico

```bash
# Fase 1: traffico normale (30 min baseline)
docker compose run --rm attacker python attacker.py --mode normal --duration 1800

# Fase 2: attacco (45 min, mostra i falsi negativi)
docker compose run --rm attacker python attacker.py --mode attack --duration 2700

# Fase 3: misto (60 min, alterna ogni 30s)
docker compose run --rm attacker python attacker.py --mode mixed --duration 3600
```

### Debug e diagnostica

```bash
# Log in tempo reale di tutti i servizi
docker compose logs -f

# Log solo dell'API (errori ES, modello caricato)
docker compose logs -f inference_api

# Log solo dell'attacker (output colored delle predictions)
docker compose logs -f attacker

# Stato cluster Elasticsearch
curl -s http://localhost:9200/_cluster/health | python3 -m json.tool

# Quanti documenti sono stati indicizzati
curl -s http://localhost:9200/traffic-logs/_count | python3 -m json.tool

# Metriche raw Prometheus dell'API
curl -s http://localhost:8000/metrics

# Test manuale di una prediction (traffico normale)
curl -s -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
    "packet_size": 500,
    "request_rate": 5,
    "connection_duration": 0.5,
    "payload_entropy": 4.5,
    "header_count": 8,
    "error_rate": 0.02,
    "unique_endpoints": 3,
    "byte_variance": 1000
  }' | python3 -m json.tool

# Test manuale di una prediction (Slowloris evasivo)
curl -s -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
    "packet_size": 498,
    "request_rate": 0.1,
    "connection_duration": 120,
    "payload_entropy": 4.5,
    "header_count": 8,
    "error_rate": 0.02,
    "unique_endpoints": 1,
    "byte_variance": 1050
  }' | python3 -m json.tool

# Riavvio singolo servizio (es. dopo modifica config)
docker compose restart grafana
docker compose restart inference_api

# Shutdown pulito con cancellazione dati
docker compose down -v
```

---

## 3. Come funziona il modello ML

### Il dataset sintetico (`model_trainer.py`)

Il modello è un `RandomForestClassifier` addestrato su **10.000 campioni sintetici**:
- 6.000 campioni benigni (60%)
- 4.000 campioni maligni (40%)

### Range delle feature nel training set

| Feature | Benigno (training) | Maligno (training) | Attacco Slowloris reale | Attacco SQLi reale |
|---|---|---|---|---|
| `packet_size` | N(500, 50) | U(1400, 2000) | N(500, 50) ✓ camuffato | U(1400, 2000) ✓ rilevato |
| `request_rate` | U(1, 10) | U(50, 200) | U(0.05, 0.2) **fuori range** | U(50, 200) ✓ rilevato |
| `connection_duration` | U(0.1, 2.0) | U(20, 120) | U(80, 150) **fuori range** | U(0.2, 1.0) ✓ ok |
| `payload_entropy` | U(3.0, 6.0) | U(6.5, 8.0) | U(3.5, 5.5) ✓ camuffato | U(7.5, 9.0) **fuori range** |
| `header_count` | U(5, 15) | U(20, 50) | N(8, 2) ✓ camuffato | U(60, 100) **fuori range** |
| `error_rate` | Beta(1,20) ≈ 0.05 | U(0.3, 0.9) | U(0.01, 0.05) ✓ camuffato | U(0.3, 0.9) ✓ rilevato |

### Perché il modello fallisce su Slowloris

Il training set di Slowloris copre `connection_duration` 20–120s con `request_rate` 50–200.  
L'attacco reale usa `connection_duration` 80–120s (overlap) ma `request_rate` **0.05–0.2** (mai visto).  
Il Random Forest non ha mai visto una connessione lunga con rate così basso → interpola verso benign.

### Hyperparameter attuali

```python
RandomForestClassifier(
    n_estimators=100,   # numero di alberi
    max_depth=8,        # profondità massima di ogni albero
    random_state=42,    # riproducibilità
    n_jobs=-1           # usa tutti i core
)
```

---

## 4. Grafana — Query, Dashboard e Alert

Grafana usa **PromQL** (Prometheus Query Language). Accesso: http://localhost:3000 (admin/minilab)

### 4.1 Dashboard preconfigurata: HPC Overview

La dashboard `hpc_overview.json` ha 4 pannelli già pronti:

| Pannello | Tipo | Query |
|---|---|---|
| Inference Latency p50/p95/p99 | Time series | `histogram_quantile(...)` |
| Predictions per secondo | Time series | `rate(predictions_total[1m])` |
| CPU Usage inference containers | Time series | `rate(container_cpu_usage_seconds_total...)` |
| Malicious vs Benign Ratio | Gauge | Ratio malicious/total |

### 4.2 Query PromQL fondamentali

Aprire **Explore** (icona bussola) → selezionare datasource Prometheus.

#### Latenza

```promql
# Latenza mediana (p50) - ultimo minuto
histogram_quantile(0.50, sum(rate(inference_latency_seconds_bucket[1m])) by (le))

# Latenza p95 - più informativa per SLA
histogram_quantile(0.95, sum(rate(inference_latency_seconds_bucket[1m])) by (le))

# Latenza p99 - worst case
histogram_quantile(0.99, sum(rate(inference_latency_seconds_bucket[1m])) by (le))

# Tutte e tre insieme (usare in un pannello time series con 3 query A/B/C)
```

#### Throughput

```promql
# Predictions al secondo per label (benign / malicious)
sum(rate(predictions_total[1m])) by (result)

# Solo malicious rate
rate(predictions_total{result="malicious"}[1m])

# Solo benign rate
rate(predictions_total{result="benign"}[1m])

# Totale predictions dall'avvio (counter cumulativo)
predictions_total
```




#### CPU e Memoria (da cAdvisor)

```promql
# CPU usage dei container inference (core utilizzati)
rate(container_cpu_usage_seconds_total{container_label_com_docker_compose_service="inference_api"}[1m])

# Memoria RSS del container inference_api (bytes)
container_memory_rss{container_label_com_docker_compose_service="inference_api"}

# CPU di tutti i container del lab
rate(container_cpu_usage_seconds_total{container_label_com_docker_compose_project="minilab-ai-security"}[1m])
```

### 4.3 Creare un nuovo pannello in Grafana

1. Aprire la dashboard HPC Overview
2. Click **Add** → **Visualization**
3. In basso nel pannello query, incollare la PromQL desiderata
4. Selezionare il tipo di grafico (Time series, Gauge, Stat, Bar chart)
5. A destra configurare titolo, unità (seconds, percent, short)
6. Click **Apply** → **Save dashboard** (icona floppy disk)

**Esempio — pannello "Confidence Media":**
- Query: `model_confidence`
- Tipo: `Stat`
- Unità: `0.0-1.0 → Percent (0-100)` oppure lasciare `none`
- Thresholds: verde > 0.75, arancio 0.60–0.75, rosso < 0.60

**Esempio — pannello "Request Rate totale":**
- Query A: `sum(rate(predictions_total[1m]))` — legend: `Total req/s`
- Query B: `rate(predictions_total{result="malicious"}[1m])` — legend: `Malicious req/s`
- Tipo: `Time series`



## 5. Kibana — Query, Dashboard e Alert

Kibana usa **KQL** (Kibana Query Language) e **ES|QL** per le query sui documenti in Elasticsearch. Accesso: http://localhost:5601

### 5.1 Dashboard preconfigurata: SOC Dashboard

Importata con `import_dashboard.sh`, contiene:

| Visualizzazione | Tipo | Campo chiave |
|---|---|---|
| Predictions Over Time | Bar chart (stacked) | `prediction_label.keyword` per tempo |
| Prediction Label Summary | Tabella | Count per `prediction_label.keyword` |
| Confidence Distribution | Istogramma | `confidence` in bucket 0.05 |

### 5.2 Discover — Esplorare i documenti

Andare in **Discover** → selezionare data view `traffic-logs*` → impostare time range su **Last 15 minutes**.