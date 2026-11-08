"""Screen user content and strip PII before it is stored or sent to a model.

Two small SIE models behind the same API:

  fastino/gliguard-LLMGuardrails-300M  -> safe / unsafe verdict   (/v1/extract)
  urchade/gliner_multi_pii-v1          -> PII spans to mask       (/v1/extract)

Commands:
  screen   guardrail verdict + redacted text for one string
  redact   redacted text for a file
  spans    list the PII spans found in a file
"""

from __future__ import annotations

import argparse
import os
import pathlib
import time

import requests
from dotenv import load_dotenv

load_dotenv()

BASE_URL = os.environ.get("SIE_BASE_URL", "https://api.superlinked.com")
API_KEY = os.environ.get("SIE_API_KEY")
if not API_KEY:
    raise SystemExit(
        "SIE_API_KEY is not set. Copy .env.example to .env and put your sk-sie- key in it."
    )

GUARD_MODEL = os.environ.get("SIE_GUARD_MODEL", "fastino/gliguard-LLMGuardrails-300M")
PII_MODEL = os.environ.get("SIE_PII_MODEL", "urchade/gliner_multi_pii-v1")

PII_LABELS = [
    "person",
    "email",
    "phone number",
    "address",
    "credit card number",
    "date of birth",
    "social security number",
]

MASK = {
    "person": "NAME",
    "email": "EMAIL",
    "phone number": "PHONE",
    "address": "ADDRESS",
    "credit card number": "CARD",
    "date of birth": "DOB",
    "social security number": "SSN",
}


def _post(path: str, payload: dict, retries: int = 5) -> dict:
    for attempt in range(retries):
        resp = requests.post(
            f"{BASE_URL}{path}",
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json",
                # SIE defaults to msgpack; ask for JSON so resp.json() works.
                "Accept": "application/json",
            },
            json=payload,
            timeout=120,
        )
        # Serverless returns 503 while a model cold-starts. Back off and retry.
        if resp.status_code in (429, 503) and attempt < retries - 1:
            try:
                delay = float(resp.headers.get("Retry-After", ""))
            except ValueError:
                delay = 2**attempt
            time.sleep(min(delay, 30))
            continue
        resp.raise_for_status()
        return resp.json()
    raise RuntimeError("unreachable")  # loop always returns or raises


def screen(text: str) -> tuple[bool, float]:
    """Return (is_safe, confidence) from the guardrail classifier."""
    out = _post(
        f"/v1/extract/{GUARD_MODEL}",
        {"items": [{"text": text}], "params": {"labels": ["safe", "unsafe"]}},
    )
    scores = {
        c["label"].lower(): float(c["score"])
        for c in out["items"][0].get("classifications", [])
    }
    return scores.get("safe", 0.0) >= scores.get("unsafe", 0.0), max(scores.values(), default=0.0)


def find_pii(text: str) -> list[dict]:
    out = _post(
        f"/v1/extract/{PII_MODEL}",
        {"items": [{"text": text}], "params": {"labels": PII_LABELS}},
    )
    spans = out["items"][0].get("entities", [])
    return sorted(spans, key=lambda e: (e["start"], -(e["end"] - e["start"])))


def mask(text: str, spans: list[dict]) -> str:
    out: list[str] = []
    cursor = 0
    for span in spans:
        start, end = span["start"], span["end"]
        if start < cursor:  # already covered by a previous span
            continue
        token = MASK.get(span["label"].lower(), span["label"].upper().replace(" ", "_"))
        out.append(text[cursor:start])
        out.append(f"[{token}]")
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def redact(text: str) -> tuple[str, list[dict]]:
    spans = find_pii(text)
    return mask(text, spans), spans


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_screen = sub.add_parser("screen", help="guardrail verdict + redacted text")
    p_screen.add_argument("text")

    p_redact = sub.add_parser("redact", help="redacted text for a file")
    p_redact.add_argument("path", type=pathlib.Path)

    p_spans = sub.add_parser("spans", help="list the PII spans found in a file")
    p_spans.add_argument("path", type=pathlib.Path)

    args = parser.parse_args()

    if args.cmd == "screen":
        safe, score = screen(args.text)
        clean, spans = redact(args.text)
        print(f"verdict: {'safe' if safe else 'unsafe'}  ({score:.3f})")
        print(f"pii: {len(spans)} span(s)")
        print(clean)
    elif args.cmd == "redact":
        clean, _ = redact(args.path.read_text(encoding="utf-8"))
        print(clean)
    elif args.cmd == "spans":
        text = args.path.read_text(encoding="utf-8")
        for span in find_pii(text):
            print(f"{span['label']:20} {span['score']:.3f}  {span['text']!r}")


if __name__ == "__main__":
    main()
