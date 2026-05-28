# Esercizio — Track AI: Migliorare il Classificatore di Traffico


## Contesto

Il laboratorio include un classificatore `RandomForestClassifier` addestrato su 10.000 campioni
sintetici di traffico di rete. Il modello distingue traffico **benigno** da traffico **maligno**
(Slowloris DoS + SQL Injection burst).

Durante la Fase 2 del laboratorio avete osservato che il modello **non rileva** l'attacco
Slowloris evasivo: lo classifica come `benign` con una confidence ≥ 0.60.

Il vostro compito è **analizzare il problema, correggere il dataset di training e migliorare
il modello**, poi validare le modifiche usando i tool di monitoraggio del lab.

---

## Background teorico

### Perché il modello fallisce?

Il training set rappresenta Slowloris con questi range:

| Feature | Range nel training (maligno) | Range nell'attacco reale |
|---|---|---|
| `request_rate` | 50–200 req/s | **0.05–0.2 req/s** ← mai visto |
| `connection_duration` | 20–120 s | 80–150 s ← parzialmente fuori |

Il Random Forest non ha mai visto una connessione lunga con un `request_rate` così basso.
Quando arriva una richiesta con `connection_duration=110` e `request_rate=0.09`, il modello
interpola verso la classe benigna perché i valori si sovrappongono con il cluster benigno
su quasi tutte le feature eccetto `connection_duration`.

Questo problema si chiama **distribution shift**: il modello è addestrato su una distribuzione
diversa da quella che trova in produzione.

### Il ciclo di vita del modello in questo lab

```
model_trainer.py → model.pkl → inference_api (FastAPI) → /predict
```

Ogni volta che modificate `model_trainer.py` e riavviate il container, il modello viene
riaddestratto da zero e il nuovo `model.pkl` viene caricato automaticamente.

---

## Setup iniziale

**1. Avviare il lab**
```bash
docker compose up -d
bash elastic/import_dashboard.sh
```

**2. Generare la baseline** (almeno 3 minuti di traffico normale)
```bash
docker compose run --rm attacker python attacker.py --mode normal --duration 180
```

**3. Lanciare la modalità attacco e osservare i falsi negativi in Kibana**
```bash
docker compose run --rm attacker python attacker.py --mode attack --duration 300
```


---

## STEP 1 — Analisi esplorativa (non scrivere ancora codice)

Prima di modificare qualsiasi cosa, usate Kibana per capire la distribuzione reale.

Aprite kibana per analizzare le distribuzioni

---

## STEP 2 — Estendere il dataset di training

Aprite `inference_api/model_trainer.py` e modificate la funzione `generate_dataset()`.

### 2.1 — Separare gli attacchi in sotto-categorie

Invece di un unico cluster "maligno", create **tre sotto-categorie distinte**:
- `n_slowloris`: Slowloris classico (quello già presente)
- `n_slowloris_evasive`: Slowloris **evasivo** con request_rate bassissimo
- `n_sqli`: SQL Injection burst

```python
def generate_dataset(n_samples: int = N_SAMPLES):
    rng = np.random.default_rng(RANDOM_STATE)

    n_benign = int(n_samples * 0.55)           # 55% benigno
    n_malicious = n_samples - n_benign

    
    n_slowloris          = int(n_malicious * 0.35)   # Slowloris classico
    n_slowloris_evasive  = int(n_malicious * 0.35)   # Slowloris evasivo ← NUOVO
    n_sqli               = n_malicious - n_slowloris - n_slowloris_evasive

    # ---- TRAFFICO BENIGNO (invariato) ----
    benign = np.column_stack([
        rng.normal(500, 50, n_benign),
        rng.uniform(1, 10, n_benign),
        rng.uniform(0.1, 2.0, n_benign),
        rng.uniform(3.0, 6.0, n_benign),
        rng.uniform(5, 15, n_benign),
        rng.beta(1, 20, n_benign),
        rng.integers(1, 6, n_benign).astype(float),
        rng.normal(1000, 200, n_benign),
    ])

    # ---- SLOWLORIS CLASSICO ----
    slowloris = np.column_stack([
        rng.uniform(1400, 2000, n_slowloris),
        rng.uniform(50, 200, n_slowloris),
        rng.uniform(20, 120, n_slowloris),
        rng.uniform(6.5, 8.0, n_slowloris),
        rng.uniform(20, 50, n_slowloris),
        rng.uniform(0.3, 0.9, n_slowloris),
        rng.integers(1, 3, n_slowloris).astype(float),
        rng.normal(5000, 800, n_slowloris),
    ])

    # ---- SLOWLORIS EVASIVO ← da completare ----
    # TODO: riempite i range basandovi sull'analisi fatta in STEP 1.
    # Suggerimento: request_rate molto basso, connection_duration molto alta,
    # ma packet_size e header_count simili al traffico benigno.
    slowloris_evasive = np.column_stack([
        # packet_size:          ???
        # request_rate:         ???  ← chiave dell'evasione
        # connection_duration:  ???  ← chiave dell'evasione
        # payload_entropy:      ???
        # header_count:         ???
        # error_rate:           ???
        # unique_endpoints:     ???
        # byte_variance:        ???
    ])

    # ---- SQL INJECTION BURST (invariato) ----
    sqli = np.column_stack([
        rng.uniform(1400, 2000, n_sqli),
        rng.uniform(50, 200, n_sqli),
        rng.uniform(0.2, 1.0, n_sqli),
        rng.uniform(7.5, 9.0, n_sqli),
        rng.uniform(60, 100, n_sqli),
        rng.uniform(0.3, 0.9, n_sqli),
        rng.integers(1, 3, n_sqli).astype(float),
        rng.normal(5000, 800, n_sqli),
    ])

    malicious = np.vstack([slowloris, slowloris_evasive, sqli])
    X = np.vstack([benign, malicious])
    y = np.array([0] * n_benign + [1] * len(malicious))

    idx = rng.permutation(len(y))
    return X[idx], y[idx]
```

> **Compito:** Completate il blocco `slowloris_evasive` con i range appropriati.

---

## STEP 3 — Sperimentare con gli hyperparameter

Modificate la funzione `train()` per sperimentare con configurazioni diverse del classificatore.

### 3.1 — Configurazione base da provare

```python
# Configurazione attuale
clf = RandomForestClassifier(
    n_estimators=100,
    max_depth=8,
    random_state=RANDOM_STATE,
    n_jobs=-1
)
```

### 3.2 — Configurazioni alternative da testare

Provate almeno **due** delle seguenti varianti e confrontate i risultati sul classification report:

```python
# Variante A — più alberi, meno profondi 
clf = RandomForestClassifier(
    n_estimators=300,
    max_depth=6,
    min_samples_leaf=5,      
    random_state=RANDOM_STATE,
    n_jobs=-1
)

# Variante B — Gradient Boosting 
from sklearn.ensemble import GradientBoostingClassifier
clf = GradientBoostingClassifier(
    n_estimators=200,
    max_depth=4,
    learning_rate=0.05,
    random_state=RANDOM_STATE
)

# Variante C — class_weight per bilanciare meglio le classi
clf = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,          # alberi profondi ma con min_samples regolato
    min_samples_split=10,
    class_weight="balanced", 
    random_state=RANDOM_STATE,
    n_jobs=-1
)
```

> **Compito:** Per ogni variante provata, annotate **precision**, **recall** e **f1-score**
> per la classe `malicious` dal classification report stampato a terminale.

---


---

## STEP 5 — Validare il miglioramento 

Dopo ogni modifica, ricostruite il container e riavviate:

```bash
# Ricostruire il modello e riavviare l'API
docker compose build inference_api
docker compose up -d inference_api

# Verificare che il nuovo modello sia caricato (cercare "Modello caricato")
docker compose logs inference_api
```

Poi rilanciate il traffico di attacco:
```bash
docker compose run --rm attacker python attacker.py --mode attack --duration 300
```


**Obiettivo:** `false_negative_rate` < 20% durante la fase di attacco.

### Metrica di successo in Grafana

In Grafana (`http://localhost:3000`), controllate il pannello **Malicious vs Benign Ratio**:
- **Prima della correzione:** ratio ≈ 0–5% durante l'attacco Slowloris
- **Dopo la correzione:** ratio ≥ 50% durante l'attacco Slowloris




---

## Riferimenti utili

- [RandomForestClassifier — scikit-learn docs](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html)
- [Classification metrics — scikit-learn](https://scikit-learn.org/stable/modules/model_evaluation.html#classification-metrics)
- [ES|QL reference — Elastic docs](https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html)

