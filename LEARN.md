# Learn — THREATLENS

## What it is

URL phishing detector. Flask app that reads a URL, extracts static features, and returns a risk score with plain-English reasons. **No ML, no model.** Every signal is an explainable heuristic — that's the point.

**Read this first, then go file-by-file in the repo.**

## 5-minute quickstart

```bash
git clone https://github.com/Santhosh595/THREATLENS && cd THREATLENS
pip install -r requirements.txt
python app.py         # check README for port
pytest -q             # run tests
```

## Concepts — the "why" behind each file

| If you see this in the code | What it means | Viva answer |
|---|---|---|
| URL parsing (`urllib.parse`) | Breaking URL into scheme/host/path | Phishing hides in the host part, not the page |
| Domain length, digit count, hyphen count | Heuristic features | Lookalikes are unusually long / digit-heavy |
| Typosquat check (compare to `paypal`, `google`...) | Detect `paypa1`, `g00gle` | Levenshtein-ish closeness to a brand = suspicious |
| Punycode (`xn--`), IDN | Internationalized domain encoding | Attackers use Unicode homoglyphs to fake brands |
| HTTPS vs HTTP scheme | Transport check | HTTP login page = major red flag |
| Subdomain count, `@` in URL, redirect params | More heuristics | `@` tricks browsers into showing a fake host |
| Flask form, `request.form` | Input handling | User input is untrusted. Validate. |
| Private-IP block (no fetching 10.x/192.168.x) | SSRF defense | The app fetches URLs? It must refuse internal addresses |

## Common pitfalls

1. **Treating heuristics as truth** — it's "suspicious, verify", not "malicious". Say this out loud in viva.
2. **Fetching attacker URLs blindly** — SSRF. Block private/loopback ranges before any fetch.
3. **Hardcoding brand list** — it's a heuristic list; say so. It will miss new brands.
4. **No False-positive thinking** — URL shorteners and CDNs legitimately look "suspicious". Own the trade-off.
5. **Storing user-submitted URLs** — don't log full URLs with query params (may contain tokens).

## Hands-on, in this order

1. Run the app, paste `https://www.google.com` → what score? Which features fired?
2. Paste `http://paypa1-secure.example.com/login` → walk through each flagged signal.
3. Paste `https://shorturl.at/example` (or any shortener) → does it false-positive? Why?
4. Open the source, find the scoring function. What weight does each feature carry? Why those weights?
5. Compare your verdict with https://www.virustotal.com/ for the same URLs.
6. Try a punycode URL: `http://xn--pypal-4ve.com` — what does the code do with `xn--`?

## Viva questions (with the trap)

1. **"Why heuristics, not ML?"** Answer: explainability + no training data needed; an ML model can't tell you *why* it flagged. Trap: pretending heuristics are "accurate".
2. **"Walk me through `paypa1.com`"** Answer: brand closeness + digits + maybe HTTP = high score. List each feature.
3. **"What's SSRF and how does this app prevent it?"** Answer: private-IP block before fetch.
4. **"What's a false positive here?"** Answer: shorteners, new legit domains, CDNs. Give an example.
5. **"What's punycode?"** Answer: ASCII-safe encoding of Unicode domains; attackers abuse it for homoglyph brands.

## 3 things to say if stuck

- "Scores are heuristic weights, not a model — here's the scoring function."
- "We trade recall for explainability on purpose."
- "Let me paste that URL and show you which signals fire."

Good luck. If you can trace one URL through every feature, you understand this repo.
