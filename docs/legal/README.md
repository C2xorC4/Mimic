# Legal templates (Mimic)

Templates for the proprietary-first distribution model. **Not legal advice**
— have counsel review before sending eval binaries or signing design-partner
agreements.

## Files in this repository

| File | Purpose |
|------|---------|
| [`LICENSE`](../../LICENSE) | Proprietary terms for **source code** in this private repo |
| [`LICENSE-GPL`](../../LICENSE-GPL) | GPLv2 notice for **eBPF kernel programs** only (`internal/ebpf/`) |
| [`EULA.txt`](../../EULA.txt) | Terms for **binary/eval** distribution to end users |

## Before first eval distribution

1. Replace placeholders:
   - `[COPYRIGHT HOLDER]` — your legal name or LLC name
   - `[CONTACT EMAIL]` — licensing contact
   - `[STATE/COUNTRY]`, `[COUNTY, STATE/COUNTRY]` — governing law (EULA)
   - `[90]` — eval term in days (EULA §1)
2. Paste the **full GPLv2 text** into `LICENSE-GPL` (placeholder notes the omission).
3. Bundle `EULA.txt` with installers or reference it from `mimic install`.
4. Optional: pair eval shipments with [`NDA-EVAL-template.md`](NDA-EVAL-template.md).

## Public demo repository (separate repo)

Use [`demo-repo-README.md`](demo-repo-README.md) as the starting README for a
public `mimic-demo` repo that contains **no proprietary source** — docs,
validation commands, and marketing assets only.

## Instrument map

```
Private mimic repo     → LICENSE (proprietary)
internal/ebpf/         → LICENSE-GPL (kernel requirement)
Shipped binary         → EULA.txt
Design partner         → NDA (optional) + EULA.txt
Paid customer          → Commercial order form / license (future; not drafted here)
```