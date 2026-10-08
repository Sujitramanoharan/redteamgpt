# RedTeamGPT operations runbook

For whoever deploys and runs the public service. Commands assume the repository root.

## How it fits together

One Docker web service on Render serves the dashboard and the API from the same origin. It
talks to a Render Postgres database over the private network and downloads the detector
model from a private Hugging Face repository at a pinned commit when it starts. Email goes out
through any SMTP provider. The Assistant tab calls the platform's own LLM key, with a daily
per-organisation cap. The `/v1` proxy calls each customer's own provider with their key,
which is stored encrypted.

```
browser / customer app ──https──▶ Render web service (Docker)
                                    ├─ FastAPI + React build
                                    ├─ detector (HF Hub @ MODEL_HUB_REVISION)
                                    ├─▶ Render Postgres (private network only)
                                    ├─▶ SMTP provider (verification, reset, invites)
                                    ├─▶ Gemini (Assistant tab, capped)
                                    └─▶ customer's LLM (/v1 proxy, their key)
```

## First deployment

Before you start, you need:

- A Hugging Face account with a **write** token (to publish the model) and a **read** token
  (for the server to download it).
- An SMTP provider. Resend, Brevo and Postmark all have free tiers. Verify your sending
  domain with them, or verification emails will land in spam.
- A Gemini API key (<https://aistudio.google.com/apikey>) if the Assistant tab should answer.
- A Render account connected to the GitHub repository.
- Your own **Terms of Service** and **Privacy Policy**. The service stores the prompts customers
  send, so you need both before opening sign-ups to the public. This project does not include them.

Steps:

1. **Publish the model** that passed evaluation (see [Promoting a model](#promoting-a-new-model)):
   ```bash
   python src/upload_model.py --repo <you>/redteamgpt-detector --path models/detector-v6 --private
   ```
   It prints `MODEL_HUB_ID` and `MODEL_HUB_REVISION`. Keep both.
2. **Push the branch** to GitHub and merge it into `main`.
3. In Render, go to **New → Blueprint**, pick the repository and apply `render.yaml`. This
   creates the web service and the database.
4. Fill in the values Render prompts for:

   | Variable | Value |
   |---|---|
   | `MODEL_HUB_ID`, `MODEL_HUB_REVISION` | from step 1 |
   | `HF_TOKEN` | the **read** token |
   | `SMTP_HOST`, `SMTP_USERNAME`, `SMTP_PASSWORD` | from your email provider |
   | `SMTP_FROM` | e.g. `RedTeamGPT <no-reply@yourdomain.com>`, on the verified domain |
   | `LLM_API_KEY` | Gemini key, or set `LLM_PROVIDER=none` |
   | `APP_BASE_URL` | leave empty until you add a custom domain |

   `ENCRYPTION_KEY` and `METRICS_TOKEN` are generated for you. **Never regenerate
   `ENCRYPTION_KEY`**: it would make every customer's stored LLM key unreadable.
5. Deploy. The container runs migrations, downloads the model and starts. The first boot takes
   a couple of minutes. It is live when `https://<service>.onrender.com/ready` returns
   `"status": "ready"` and shows the expected `model_info.weights_sha256`.
6. **Refusals at boot are deliberate.** If the log says `Refusing to start:`, a production
   check failed (SQLite, open CORS, no SMTP, short encryption key, non-https URL). Fix the
   variable it names.
7. Sign up through the website as a normal user, then make yourself the operator from the
   service's **Shell** tab:
   ```bash
   python src/manage.py make-admin you@yourdomain.com
   ```
8. Send one real sign-up to an address you control, and check that the email arrives and isn't
   in spam.

### Free plan (no card)

`render.free.yaml` deploys the web service on Render's free plan. The database
is a free Neon Postgres, because Render allows one free database per account.

1. On **neon.tech**, create a free project in the Singapore region (AWS
   ap-southeast-1) and copy its connection string (`postgresql://...?sslmode=require`).
2. In Render, go to **New → Blueprint**, pick the repository, and set
   **Blueprint Path** to `render.free.yaml`.
3. Enter `DATABASE_URL` (the Neon string), `HF_TOKEN` (a Hugging Face read
   token) and, optionally, `LLM_API_KEY`. Everything else is preset.

What to expect, measured with a 512 MB / 0.1 CPU container:

- Memory fits, with a peak of 469 MB under a burst of long prompts. This
  relies on the fp16 ONNX model, the arena-free ONNX session, the lightweight
  tokenizer and `MAX_CONCURRENT_INFERENCES=1`.
- Normal scans take about 0.4 s. Very long prompts take about 15 s, and a
  100-passage document takes several minutes.
- The service sleeps after about 15 minutes without visitors, and the first
  request afterwards takes 1–2 minutes.

Use it for demos and trials. Move to `render.yaml` (Standard plan) for real
users.

### Custom domain

Add the domain under the service's **Settings → Custom Domains**. Render issues the TLS
certificate. Then set `APP_BASE_URL=https://yourdomain.com` so links in emails point there,
and redeploy.

## Promoting a new model

Never overwrite the model in production. Train a candidate alongside the current one, compare
the two, and switch only if the candidate wins.

```bash
python src/heldout.py                  # held-out set: never trained on
python src/extra_data.py               # training set; fails if it overlaps held-out
python src/train_detector.py --model models/distilbert-base-uncased \
    --data data/combined_v6.csv --output models/detector-next --epochs 2
# (add --resume to continue after an interruption)

MODEL_DIR=models/detector-next python src/eval_heldout.py --save results/heldout-next.json
python src/eval_heldout.py --compare results/heldout-v6.json results/heldout-next.json
MODEL_DIR=models/detector-next python src/benchmark.py
```

Promote only if **all** of the following hold:

- the benchmark shows no category that regressed;
- held-out attack recall is no lower;
- the false-positive rate is no higher, especially on `toxicchat-test-benign` (real users) and `fp-probe`.

Then:

1. `python src/export_onnx.py --model models/detector-next` **(required: the production
   image only runs ONNX)**. If it reports no passing candidate, do not promote the model.
2. `python src/upload_model.py --repo <you>/redteamgpt-detector --path models/detector-next --private`
3. In Render, set `MODEL_HUB_REVISION` to the printed commit and redeploy.
4. Confirm `/ready` shows the new `weights_sha256`.

**Rollback:** set `MODEL_HUB_REVISION` back to the previous commit and redeploy. Old revisions
stay on the Hub.

Customer feedback reaches training only from organisations that opted in (Settings → Data &
privacy). Download it as the operator:

```bash
curl -X POST https://<host>/api/admin/training-export -b "rtg_session=…" \
  -H "X-CSRF-Token: …" -o review_feedback.csv
```

Read every row before adding it to training data: a customer's reviewer can be wrong, or
malicious.

## Routine operations

| Task | How |
|---|---|
| Health | Render checks `/ready` (model loaded and database reachable). Check `/health` for liveness only. |
| Metrics | `curl -H "Authorization: Bearer $METRICS_TOKEN" https://<host>/metrics` (Prometheus format). |
| Logs | Render **Logs** tab, JSON lines. Each request carries `request_id`; customers can send `X-Request-ID` to correlate. |
| Errors | Set `SENTRY_DSN`. Prompts and emails are never sent to Sentry. |
| Usage | `python src/manage.py stats`, or `GET /api/admin/stats` as the operator. |
| Stop sign-ups | Set `SIGNUP_ENABLED=false`. Existing users are unaffected. |
| Lock an abusive user | `python src/manage.py disable-user <email>`. This signs them out everywhere. Revoke their org's keys too if needed. |
| Retention | Each org sets its own (1–365 days). A background job deletes expired logs, sessions and links every 6 hours. |

## Secrets

| Secret | Rotating it |
|---|---|
| `METRICS_TOKEN`, `SMTP_*`, `LLM_API_KEY`, `HF_TOKEN` | Change in Render and redeploy. There's no user impact. |
| `ENCRYPTION_KEY` | **Avoid.** Every customer's stored upstream key becomes unreadable, and the proxy returns 502 until each customer re-enters it. If it leaked, rotate anyway and tell customers to re-enter their keys and rotate them with their provider. |
| Database password | Rotate in Render's database settings. `DATABASE_URL` updates automatically, then redeploy. |

API keys are stored only as SHA-256 hashes, and passwords as Argon2id hashes. Neither can be
recovered from a database copy.

## Backups and restore

Render Postgres takes daily backups on paid plans; restore them from the database's
**Recovery** tab. Before risky changes, take your own:

```bash
pg_dump "$DATABASE_URL" --format=custom --file=redteamgpt-$(date +%F).dump
pg_restore --clean --no-owner --dbname "$DATABASE_URL" redteamgpt-YYYY-MM-DD.dump
```

Schema changes go through Alembic only:
`alembic revision --autogenerate -m "..."`, then review the file, commit it, and deploy. The
container applies it on start.

## Incidents

| Symptom | Likely cause | Action |
|---|---|---|
| `/ready` 503, `model: unavailable` | Model download failed (bad token or revision), or out of memory | Check the logs for the Hub error, verify `HF_TOKEN` and `MODEL_HUB_REVISION`, and check memory in Metrics |
| `/ready` 503, `database: unavailable` | Database down or credentials rotated | Check the database status in Render, and redeploy after rotating credentials |
| API returns 503 "firewall could not analyse" | Detection is raising exceptions | This fails closed by design. Check the logs for the traceback and roll back the model revision if it started after a promotion. |
| Sign-up emails missing | SMTP misconfigured or domain not verified | Look for `Failed to send` in the logs, and check the provider dashboard |
| Many 429s | One customer bursting, or an attack | Limits are per key/session (`RATE_LIMIT_PER_MINUTE`) and per IP for sign-in. Raise only for known customers. |
| Proxy 502 "cannot be decrypted" | `ENCRYPTION_KEY` changed | Restore the previous value, or have the customer re-enter their key |

## Scaling

The production image serves the model with ONNX Runtime and does not install torch.
Measured on v5, same prompts:

| Backend | Private memory per worker | Verdict agreement with PyTorch | Speed |
|---|---|---|---|
| PyTorch (`requirements.txt`) | ~1,320 MB | reference | 1× |
| ONNX fp32, no torch (`requirements-runtime.txt`) | ~620 MB | 100% (1,238 prompts, 0 flips) | ~2.6× faster |

int8 quantisation was rejected: it flipped 24–46 verdicts. `src/export_onnx.py` repeats this
check for every new model and only writes `model.onnx` if agreement is at least 99.5%.

Each worker loads its own copy of the model, so on Render's 2 GB Standard plan
`WEB_CONCURRENCY=2` fits comfortably. The 512 MB Starter plan does not. Scale in this order:

1. `WEB_CONCURRENCY=2` on Standard, then a larger plan.
2. More instances, with `REDIS_URL` set (for example, Render Key Value) so rate limits are
   shared across them.

The database holds all other state. Re-measure throughput after any model change:
`python src/loadtest.py --api-key <key>` against a server started with
`RATE_LIMIT_PER_MINUTE=100000`.

## Known limitations

- **Detection is not perfect.** See the held-out numbers in the README. Soft persona and
  paraphrase attacks are the weakest category. Tell customers to treat this as one layer of
  defence, not the only one.
- The `/v1` proxy screens the **latest user message** only, and does not support streaming.
- One organisation per user account.
- **Training-data licences.** Two training sets are CC BY-NC 4.0 (non-commercial): `tatsu-lab/alpaca`
  (used since v1) and `lmsys/toxic-chat` (v6). `xTRam1/safe-guard-prompt-injection` (v6)
  declares no licence at all. `databricks-dolly-15k` is CC BY-SA 3.0 and needs attribution.
  This matters as soon as the service earns money, including paid plans or ads. **Before you
  charge anyone, get legal advice, or retrain without those three sets** (drop them in
  `src/extra_data.py` and `src/data_prep.py`, then re-run the promotion checks).
