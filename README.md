# AI Guardrail

AI Guardrail is an enterprise AI data-loss-prevention gateway. It inspects employee prompts before they reach AI systems, detects sensitive corporate data, applies policy decisions, redacts risky content, routes approved prompts to safe model tiers, inspects model responses, and records audit evidence.

This implementation is a portfolio-ready local demo. It does not call external LLM providers and does not require API keys. Prompts are inspected locally and stored only in the local SQLite database under `data/`, which is ignored by Git.

## Core Capabilities

- Corporate AI gateway with prompt inspection and simulated model routing
- Sensitive data detection for credentials, tokens, private keys, PII, payment data, internal URLs, source code, contracts, financial reports, medical records, and prompt injection
- Risk classification: Low, Medium, High, Critical
- Policy actions: allow, warn, redact, manager approval, security approval, block
- Redaction preview before routing
- Response inspection before delivery
- Audit logs with user, department, role, timestamp, risk score, action, model route, IP, device, browser, findings, and approval status
- Approval workflow for manager and security review
- Analytics dashboard for blocked, allowed, redacted, department usage, highest-risk users, common secret types, and model usage
- SIEM-ready JSON event endpoint and CSV export
- Enterprise policy and compliance mapping for ISO 27001, SOC 2, NIST CSF, NIST AI RMF, OWASP LLM Top 10, PCI DSS, HIPAA, GDPR, and DPDP Act

## Stack

- Frontend: React, Vite, Tailwind CSS, lucide-react
- Backend: FastAPI, Pydantic, SQLite
- Deployment: Docker Compose

## Run With Docker

```bash
docker compose up --build
```

Frontend: http://localhost:5173  
Backend API: http://localhost:8000/docs

## Local Development

Backend:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

## API Overview

- `POST /api/guardrail/inspect` inspects a prompt and returns a policy decision.
- `POST /api/guardrail/chat` runs the full local gateway flow with response inspection.
- `POST /api/guardrail/response-inspect` inspects a model response.
- `GET /api/guardrail/logs` returns audit logs.
- `GET /api/guardrail/logs/export.csv` exports audit logs.
- `GET /api/guardrail/analytics` returns dashboard metrics.
- `GET /api/guardrail/policies` returns sample enterprise policies.
- `POST /api/guardrail/approvals` creates an approval request.
- `GET /api/guardrail/siem/{log_id}` returns a SIEM-normalized event.

## Data Handling

The repository intentionally excludes local data and secrets:

- `.env` and `.env.*`
- local SQLite files under `data/`
- virtual environments
- dependency folders
- build outputs
- Python cache files

Do not commit real employee prompts, customer data, credentials, reports, private keys, or production configuration.

## Architecture

```mermaid
flowchart LR
  Employee --> Portal[AI Guardrail Portal]
  Portal --> Scanner[Prompt Scanner]
  Scanner --> DLP[DLP Engine]
  DLP --> Policy[Policy Engine]
  Policy --> Approval[Approval Workflow]
  Policy --> Router[Model Router]
  Router --> LLM[Enterprise or Internal LLM]
  LLM --> Response[Response Scanner]
  Response --> Employee
  Policy --> Audit[Audit Logger]
  Audit --> SIEM[SIEM Export]
```

## Production Roadmap

For production, replace demo components with enterprise services:

- PostgreSQL for audit logs, Redis for queues, and object storage for approved files
- SSO with Azure AD, Google OAuth, SAML, or LDAP
- OPA for centralized policy evaluation
- Presidio, spaCy, YARA, and managed DLP services for deeper classification
- Vault or cloud KMS for secrets
- Real OpenAI, Azure OpenAI, Gemini, Claude, Ollama, or internal LLM routing
- Slack, Teams, email, webhook, Splunk, Sentinel, Elastic, QRadar, and Chronicle integrations
- Kubernetes deployment with network policies, ingress, TLS, and persistent storage
