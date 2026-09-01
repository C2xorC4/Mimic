# Legal templates (Mimic)

Templates for distribution. **Not legal advice** — have counsel review
before sending eval binaries or signing design-partner agreements.

## Files in this repository

| File | Purpose |
|------|---------|
| [`LICENSE`](../../LICENSE) | PolyForm Shield 1.0.0 for **source** (use/modify/share; no competing product) |
| [`LICENSE-GPL`](../../LICENSE-GPL) | GPLv2 notice for **eBPF kernel programs** only (`internal/ebpf/`) |
| [`EULA.txt`](../../EULA.txt) | Terms for **binary/eval** distribution to end users |

## Before first eval distribution

1. Replace remaining placeholders in `EULA.txt` (and NDA template):
   - `[COPYRIGHT HOLDER]` — legal name or LLC name
   - `[CONTACT EMAIL]` — licensing contact
   - `[STATE/COUNTRY]`, `[COUNTY, STATE/COUNTRY]` — governing law
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
Source tree            → LICENSE (PolyForm Shield 1.0.0)
internal/ebpf/         → LICENSE-GPL (kernel requirement)
Shipped binary         → EULA.txt
Design partner         → NDA (optional) + EULA.txt
Paid / non-compete exception → Commercial license (licensor can always grant one)
```