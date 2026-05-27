
import argparse
import os
import random
import sys
import time
from datetime import datetime

import numpy as np
import requests
from rich.console import Console
from rich.text import Text

console = Console()

TARGET_URL = os.getenv("TARGET_URL", "http://inference_api:8000")
PREDICT_URL = f"{TARGET_URL}/predict"

RNG = np.random.default_rng()



def normal_features() -> dict:
    return {
        "packet_size": float(RNG.normal(500, 50)),
        "request_rate": float(RNG.uniform(1, 10)),
        "connection_duration": float(RNG.normal(0.5, 0.1)),
        "payload_entropy": float(RNG.uniform(3.0, 6.0)),
        "header_count": float(RNG.normal(8, 2)),
        "error_rate": float(RNG.beta(1, 20)),
        "unique_endpoints": float(RNG.integers(1, 6)),
        "byte_variance": float(RNG.normal(1000, 200)),
    }


def attack_features(attack_type: str) -> dict:
    """Genera feature di attacco """
    if attack_type == "slowloris":
        return {
            "packet_size": float(RNG.normal(500, 50)),           
            "request_rate": float(RNG.uniform(0.05, 0.2)),      
            "connection_duration": float(RNG.uniform(80, 150)),  
            "payload_entropy": float(RNG.uniform(3.5, 5.5)),     
            "header_count": float(RNG.normal(8, 2)),             
            "error_rate": float(RNG.uniform(0.01, 0.05)),        
            "unique_endpoints": float(RNG.integers(1, 3)),
            "byte_variance": float(RNG.normal(1100, 200)),
        }
    else:  # sqli burst
        return {
            "packet_size": float(RNG.uniform(1400, 2000)),
            "request_rate": float(RNG.uniform(50, 200)),
            "connection_duration": float(RNG.uniform(0.2, 1.0)),
            "payload_entropy": float(RNG.uniform(7.5, 9.0)),     
            "header_count": float(RNG.uniform(60, 100)),         
            "error_rate": float(RNG.uniform(0.3, 0.9)),
            "unique_endpoints": float(RNG.integers(1, 3)),
            "byte_variance": float(RNG.normal(5000, 800)),
        }




def send_request(features: dict, mode_label: str) -> None:
    ts = datetime.now().isoformat(timespec="seconds")
    try:
        resp = requests.post(PREDICT_URL, json=features, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        label_str = data.get("label_str", "?")
        confidence = data.get("confidence", 0.0)

        color = "green" if label_str == "benign" else "red"
        line = Text()
        line.append(f"[{ts}] ", style="dim")
        line.append(f"mode={mode_label:<8} ", style="cyan")
        line.append(f"prediction={label_str:<10} ", style=color + " bold")
        line.append(f"confidence={confidence:.3f}", style="yellow")
        console.print(line)
    except Exception as exc:
        console.print(f"[{ts}] [red]ERROR[/red] {exc}")



def run_normal(duration: float) -> None:
    deadline = time.time() + duration
    while time.time() < deadline:
        send_request(normal_features(), "normal")
        time.sleep(random.uniform(0.5, 2.0))


def run_attack(duration: float) -> None:
    deadline = time.time() + duration
    burst_count = 0
    while time.time() < deadline:
        if burst_count > 0 and burst_count % 5 == 0:
            send_request(normal_features(), "normal(decoy)")
            time.sleep(random.uniform(0.5, 1.5))
        else:
            atype = random.choice(["slowloris", "sqli"])
            send_request(attack_features(atype), f"attack/{atype}")
            time.sleep(random.uniform(0.1, 0.5))
        burst_count += 1


def run_mixed(duration: float) -> None:
    deadline = time.time() + duration
    segment = 30  # secondi per segmento
    while time.time() < deadline:
        seg_end = min(time.time() + segment, deadline)
        mode = random.choice(["normal", "attack"])
        console.rule(f"[bold magenta]Switching to mode: {mode}[/bold magenta]")
        if mode == "normal":
            while time.time() < seg_end:
                send_request(normal_features(), "normal")
                time.sleep(random.uniform(0.5, 2.0))
        else:
            burst_count = 0
            while time.time() < seg_end:
                if burst_count > 0 and burst_count % 5 == 0:
                    send_request(normal_features(), "normal(decoy)")
                    time.sleep(random.uniform(0.5, 1.5))
                else:
                    atype = random.choice(["slowloris", "sqli"])
                    send_request(attack_features(atype), f"attack/{atype}")
                    time.sleep(random.uniform(0.1, 0.5))
                burst_count += 1



def main():
    parser = argparse.ArgumentParser(description="Attacker")
    parser.add_argument(
        "--mode",
        choices=["normal", "attack", "mixed"],
        default=os.getenv("MODE", "normal"),
        help="Modalità di traffico",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=300,
        help="Durata in secondi (default: 300)",
    )
    args = parser.parse_args()

    console.rule(f"[bold]Attacker — mode={args.mode} duration={args.duration}s[/bold]")

    
    for attempt in range(30):
        try:
            r = requests.get(f"{TARGET_URL}/health", timeout=5)
            if r.status_code == 200:
                console.print("[green]inference_api raggiungibile.[/green]")
                break
        except Exception:
            pass
        console.print(f"[yellow]Attendo inference_api... ({attempt+1}/30)[/yellow]")
        time.sleep(5)
    else:
        console.print("[red]inference_api non raggiungibile. Esco.[/red]")
        sys.exit(1)

    if args.mode == "normal":
        run_normal(args.duration)
    elif args.mode == "attack":
        run_attack(args.duration)
    else:
        run_mixed(args.duration)

    console.rule("[bold green]Completato.[/bold green]")


if __name__ == "__main__":
    main()
