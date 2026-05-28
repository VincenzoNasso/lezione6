# Esercizio — Track Cyber: Adversarial Evasion Attack


## Contesto

Il laboratorio simula un sistema di difesa basato su AI: ogni richiesta di rete viene analizzata
da un `RandomForestClassifier` che la classifica come **benigna** o **maligna**.

Il sistema sembra funzionare bene: rileva quasi tutti gli attacchi SQL Injection e parte degli
attacchi Slowloris. Ma ogni sistema difensivo ha punti ciechi.

Il vostro compito è quello del **Red Team**: analizzare il comportamento del classificatore
tramite i tool di monitoraggio, capire dove il modello è debole, e progettare un nuovo vettore
di attacco che evada la detection rimanendo sotto il radar.

Questo tipo di attività si chiama **Adversarial Machine Learning** ed è una delle sfide più
rilevanti nella sicurezza moderna.

---

## Background teorico

### Come funziona il classificatore

Il modello riceve **8 feature numeriche** che descrivono una connessione di rete:

| Feature | Descrizione |
|---|---|
| `packet_size` | Dimensione media dei pacchetti (byte) |
| `request_rate` | Numero di richieste al secondo |
| `connection_duration` | Durata della connessione (secondi) |
| `payload_entropy` | Entropia del payload (0=ripetitivo, 9=casuale) |
| `header_count` | Numero di header HTTP |
| `error_rate` | Tasso di errori HTTP (4xx/5xx) |
| `unique_endpoints` | Numero di endpoint distinti contattati |
| `byte_variance` | Varianza nella dimensione dei pacchetti |

L'output è una **label** (`benign`/`malicious`) e una **confidence** (0.0–1.0).

### Il concetto di "decision boundary"

Un classificatore divide lo spazio delle feature in regioni: da un lato la zona "benigna",
dall'altro la zona "maligna". Il vostro obiettivo è **rimanere nella zona benigna pur
eseguendo un attacco reale**.

```
         feature_A (es. request_rate)
    0 ──────────────────────────────────► alto
    │
    │   [zona BENIGNA]  │  [zona MALIGNA]
    │                   │
    │     normale        │   SQLi burst / Slowloris classico
    │                   │
    ▼
    feature_B
    (es. connection_duration)
```

Un attacco **evasivo** si posiziona nella zona benigna con feature camuffate.

### Principio di "Adversarial Perturbation"

In Machine Learning, una **Adversarial Perturbation** è una modifica minimale all'input
che causa un cambio di classificazione. In questo caso:
- Ridurre `request_rate` a valori "benigni" mentre si mantiene la connessione aperta
- Simulare packet_size e header_count tipici del traffico normale

---

## Setup iniziale

**1. Avviare il lab**
```bash
docker compose up -d
bash elastic/import_dashboard.sh
```

**2. Aprire Kibana e Grafana in due tab del browser**
- Kibana: http://localhost:5601
- Grafana: http://localhost:3000 (admin / minilab)

**3. Lanciare traffico normale come baseline (3 minuti)**
```bash
docker compose run --rm attacker python attacker.py --mode normal --duration 180
```

**4. Lanciare l'attacco già presente e osservare cosa rileva il modello**
```bash
docker compose run --rm attacker python attacker.py --mode attack --duration 180
```

---

## STEP 1 — Ricognizione: analizzare il modello come black-box

Prima di scrivere codice, dovete capire dove il modello è vulnerabile. Usate solo gli
strumenti di monitoraggio — come farebbe un attaccante reale che ha accesso ai log.

### 1.1 — Osservare la confidence durante l'attacco

In Grafana → pannello **Inference Latency / Malicious Ratio**: notate che il ratio
malicious è alto durante SQLi ma basso durante Slowloris.

In Kibana → **Discover** → `traffic-logs*`, cercate:
```kql
prediction_label: "benign" AND confidence < 0.75
```

### 1.3 — Sondare manualmente il confine di decisione

Usate `curl` per testare predizioni manuali e trovare i valori limite:

```bash
# Test 1: Slowloris con request_rate bassissimo → dovrebbe essere benign
curl -s -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
    "packet_size": 510,
    "request_rate": 0.08,
    "connection_duration": 100,
    "payload_entropy": 4.2,
    "header_count": 9,
    "error_rate": 0.02,
    "unique_endpoints": 2,
    "byte_variance": 980
  }' | python3 -m json.tool
```

```bash
# Test 2: aumentate connection_duration fino a 200 — a che valore cambia la prediction?
curl -s -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
    "packet_size": 510,
    "request_rate": 0.08,
    "connection_duration": 200,
    "payload_entropy": 4.2,
    "header_count": 9,
    "error_rate": 0.02,
    "unique_endpoints": 2,
    "byte_variance": 980
  }' | python3 -m json.tool
```

> **Compito:** Eseguite almeno 5 test manuali variando sistematicamente una feature alla volta.
> Costruite una tabella con i valori testati e le confidence ottenute.

---

## STEP 2 — Progettare il profilo dell'attacco evasivo

Basandovi sulla ricognizione dello STEP 1, progettate i range delle feature per un nuovo
tipo di attacco che:

1. **Evada il classificatore** (classificato come `benign` con confidence ≥ 0.65)
2. **Sia funzionalmente un attacco reale** (non solo rumore casuale)
3. **Sia distinguibile dal traffico benigno** per almeno un segnale comportamentale

### Opzioni di attacco (sceglierne una o combinarle)

**Opzione A — Slowloris Ultra-Lento (rate stepping)**  
Slowloris invia header HTTP incompleti per tenere aperta la connessione.
Un attaccante sofisticato può ridurre ulteriormente il rate e variarlo casualmente
per imitare un client lento ma legittimo (es. mobile con connessione scarsa).
- `request_rate`: 0.005–0.05 req/s (sotto il minimo benigno di 1 req/s)
- `connection_duration`: 150–400 s (molto sopra il massimo benigno di 2 s)
- Tutte le altre feature: range benigni

**Opzione B — Low-and-Slow SQLi**  
SQL Injection eseguita molto lentamente per non attivare soglie di rate.
Invece di 50–200 req/s, inviare 2–5 req/s con payload SQL ad alta entropia.
- `request_rate`: 2–5 req/s (si sovrappone con il benigno)
- `payload_entropy`: 6.5–7.5 (alta ma non oltre la soglia)
- `header_count`: 15–20 (appena sopra il normale)

**Opzione C — Hybrid Camouflage (avanzato)**  
Combinare caratteristiche di entrambi: connessione lunga, rate medio, entropy media.
L'obiettivo è stare in una zona grigia dove nessuna singola feature è anomala.

### Template da compilare

Compilate questa tabella prima di scrivere il codice:

| Feature | Range benigno (training) | Range malicious (training) | Vostro attacco evasivo |
|---|---|---|---|
| `packet_size` | N(500, 50) | U(1400, 2000) | ??? |
| `request_rate` | U(1, 10) | U(50, 200) | ??? |
| `connection_duration` | U(0.1, 2.0) | U(20, 120) | ??? |
| `payload_entropy` | U(3.0, 6.0) | U(6.5, 8.0) | ??? |
| `header_count` | U(5, 15) | U(20, 50) | ??? |
| `error_rate` | Beta(1,20) ≈ 0.05 | U(0.3, 0.9) | ??? |
| `unique_endpoints` | 1–5 | 1–2 | ??? |
| `byte_variance` | N(1000, 200) | N(5000, 800) | ??? |

> **Giustificate ogni scelta**: per ogni feature, spiegate perché avete scelto quel range
> e cosa intendete "simulare" a livello di comportamento di rete.

---

## STEP 3 — Implementare il nuovo attacco in `attacker.py`

Aprite `attacker/attacker.py` e aggiungete una nuova funzione di generazione delle feature.

### 3.1 — Aggiungere la funzione `stealth_attack_features()`

Trovate la funzione `attack_features()` (circa riga 25) e aggiungete dopo di essa:

```python
def stealth_attack_features() -> dict:
    """
    Attacco evasivo: progettato per bypassare il classificatore RF.
    
    Strategia: [descrivete qui la vostra strategia in 1-2 righe]
    
    Feature camuffate (simili al benigno):
      - packet_size:         ???  (giustificazione: ...)
      - request_rate:        ???  (giustificazione: ...)
      ...
    
    Segnale di attacco reale:
      - connection_duration: molto alta → connessione tenuta aperta intenzionalmente
    """
    return {
        "packet_size":          float(RNG.???),   # completare
        "request_rate":         float(RNG.???),   # completare
        "connection_duration":  float(RNG.???),   # completare
        "payload_entropy":      float(RNG.???),   # completare
        "header_count":         float(RNG.???),   # completare
        "error_rate":           float(RNG.???),   # completare
        "unique_endpoints":     float(RNG.???),   # completare
        "byte_variance":        float(RNG.???),   # completare
    }
```

### 3.2 — Aggiungere la modalità `stealth` al runner

Trovate la funzione `run_attack()` e aggiungete una nuova funzione:

```python
def run_stealth(duration: float) -> None:
    """
    Invia solo attacchi stealth a frequenza controllata.
    Simula un attaccante che vuole stare sotto il radar.
    """
    deadline = time.time() + duration
    while time.time() < deadline:
        send_request(stealth_attack_features(), "stealth")
        # Aggiungere jitter casuale per sembrare traffico umano
        time.sleep(random.uniform(???, ???))   # decidete il delay appropriato
```

### 3.3 — Registrare la nuova modalità nel parser

Trovate la funzione `main()` e aggiornate:

```python
parser.add_argument(
    "--mode",
    choices=["normal", "attack", "mixed", "stealth"],   # aggiungere "stealth"
    ...
)

# E nel blocco if/elif alla fine:
elif args.mode == "stealth":
    run_stealth(args.duration)
```

---

## STEP 4 — Validare l'evasione

### 4.1 — Ricostruire e testare

```bash
# Ricostruire il container attacker con le modifiche
docker compose build attacker

# Testare la nuova modalità stealth
docker compose run --rm attacker python attacker.py --mode stealth --duration 300
```

**Obiettivo:** `evasion_rate` ≥ 80%


---

## STEP 5 — Proposta di countermeasure (Blue Team response)

### 5.1 — Creare una Kibana Alert Rule basata su soglie deterministiche

In Kibana → **Stack Management** → **Rules** → **Create rule**

```
Nome: Stealth Connection Alert
Tipo: Elasticsearch query
Index: traffic-logs*
KQL: prediction_label: "benign" AND features.connection_duration > 100 AND features.request_rate < 1
Condizione: count > 3 in 5 minuti
Schedule: check ogni 2m
Messaggio: "Possibile attacco Slowloris evasivo: {{context.hits.total.value}} connessioni anomale"
```

### 5.2 — Creare un pannello Grafana per il segnale che il ML manca

In Grafana → **Add panel** → **New visualization**

```promql
# Ratio di "benign" con confidence bassa (zona di incertezza)
# Questo sale quando arrivano attacchi evasivi che confondono il modello
model_confidence
```

Configurate una threshold: 
- Verde: confidence > 0.80
- Giallo: confidence 0.65–0.80
- Rosso: confidence < 0.65

> **Compito:** Scrivete una regola KQL/PromQL che rilevi il vostro attacco specifico
> senza modificare il modello ML. Giustificate perché questa regola non genererebbe
> troppi falsi positivi sul traffico normale.

## Riferimenti utili

- [MITRE ATT&CK — Defense Evasion Tactic](https://attack.mitre.org/tactics/TA0005/)
- [Adversarial Machine Learning — NIST](https://csrc.nist.gov/publications/detail/white-paper/2023/03/08/adversarial-machine-learning-taxonomy-and-terminology/final)
- [Slowloris Attack — Cloudflare](https://www.cloudflare.com/it-it/learning/ddos/ddos-attack-tools/slowloris/)
- [CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)


---

## Appendice: Distribuzione delle API calls per eseguire il sondaggio manuale

Se volete automatizzare il sondaggio del decision boundary (black-box probing), potete usare
questo script Python come punto di partenza:

```python
import requests
import numpy as np

TARGET = "http://localhost:8000/predict"

# Sondare il decision boundary su request_rate
for rate in np.linspace(0.05, 15, 30):
    payload = {
        "packet_size": 500.0,
        "request_rate": float(rate),
        "connection_duration": 110.0,   # valore fisso alto
        "payload_entropy": 4.5,
        "header_count": 9.0,
        "error_rate": 0.02,
        "unique_endpoints": 2.0,
        "byte_variance": 1000.0,
    }
    r = requests.post(TARGET, json=payload).json()
    print(f"request_rate={rate:.2f} → {r['label_str']:<10} confidence={r['confidence']:.3f}")
```

> Eseguite questo script e tracciate un grafico confidence vs request_rate.
> Dove si trova il confine di decisione?
