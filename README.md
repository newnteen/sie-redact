# sie-redact

Screen user-generated content and strip PII before it reaches storage or an LLM.

A UGC app gets messy input: a threat one minute, a card number and a home address
the next. Sending that raw to a model or a database is a problem. This repo puts
two small SIE models in front of the text — a guardrail classifier and a PII
extractor — so the caller gets a verdict and a redacted copy without a frontier
model anywhere in the path.

## What it does

| Step | Model | Endpoint |
| --- | --- | --- |
| Safe / unsafe verdict | `fastino/gliguard-LLMGuardrails-300M` | `/v1/extract` |
| Detect and mask PII | `urchade/gliner_multi_pii-v1` | `/v1/extract` |

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env          # then put your sk-sie- key in .env
```

## Run

```bash
python redact.py redact sample_ticket.txt
python redact.py spans sample_ticket.txt
python redact.py screen "This is Dana Whitfield, reach me at dana@example.com."
```

## Example output

```
$ python redact.py redact sample_ticket.txt
From: [NAME] <[EMAIL]>
Subject: refund never arrived

Hi, my order from 2026-10-28 was paid with card [CARD].
The refund still hasn't arrived. My phone is [PHONE] and my
personal email is [EMAIL]. If you need to post
anything, I'm at [ADDRESS]. Date of birth on
file is [DOB]. Thanks.

$ python redact.py spans sample_ticket.txt
person               0.998  'Dana Whitfield'
email                0.571  'dana.whitfield@northwind.example'
credit card number   0.997  '4539 1488 0343 6467'
phone number         1.000  '+44 20 7946 0958'
email                0.993  'd.whitfield@personal.example'
address              0.974  '12 Elm Grove, Manchester M20 4AB'
date of birth        0.983  '1979-04-02'

$ python redact.py screen "This is Dana Whitfield, reach me at dana@example.com. I know where you live and I will make you pay."
verdict: unsafe  (1.000)
pii: 2 span(s)
This is [NAME], reach me at [EMAIL]. I know where you live and I will make you pay.
```

## Notes

- Both steps are task models on SIE Serverless (`https://api.superlinked.com`), so
  the same code runs against a self-hosted SIE Cluster with only `SIE_BASE_URL`
  changed. That is the intended target: text never leaves the network.
- PII labels and the mask tokens are configured at the top of `redact.py`. Add more
  entity types (the extractor is zero-shot) by extending `PII_LABELS`.
- Overlapping spans are collapsed: the first span wins and the rest of the text
  keeps its original characters.

## License

MIT
