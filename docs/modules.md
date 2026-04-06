# Modules Reference

Drogonsec uses a systematic naming convention: **`DRG-0x[number]`**. Each module is self-contained and focused on a specific security domain.

---

## Module Overview

| Module | Name | Status | Description |
|---|---|---|---|
| `DRG-0x1` | Core Engine | ✅ Stable | Foundation layer, CLI, config management |
| `DRG-0x2` | Neural Threat Scanner | ✅ Stable | AI-assisted threat detection and analysis |

---

## DRG-0x1 — Core Engine

Handles CLI, configuration, module orchestration, output formatting, logging and error handling. Runs implicitly on every execution.

---

## DRG-0x2 — Neural Threat Scanner

Applies intelligence-based techniques to identify, classify, and score threats.

### Pipeline

\`\`\`
Input → Preprocessing → Feature Extraction → Threat Analysis → Output
\`\`\`

### Output Fields

| Field | Type | Description |
|---|---|---|
| `threat_id` | string | Unique identifier |
| `severity` | string | low / medium / high / critical |
| `score` | float | 0.0 – 1.0 |
| `type` | string | Threat category |
| `description` | string | Human-readable explanation |
| `timestamp` | string | ISO 8601 detection time |

---

## Adding Custom Modules

1. Create a package under `./internal/modules/drg0x[N]/`
2. Implement the module interface from Core Engine
3. Register in main configuration
4. Rebuild with `make install`
