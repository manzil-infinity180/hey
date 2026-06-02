# Securing this repo's supply chain with cilock

This fork is a testbed for **[cilock](https://github.com/aflock-ai/rookery)** (a.k.a. CI/lock) —
a tool that wraps any build/test/scan command and produces a **signed, in-toto
attestation** of exactly what happened: the process tree, every file read or
written, and every network connection — captured **kernel-side with eBPF**.

Two claims we're testing:

- **Zero configuration** — no `.witness.yaml`, no attestor flags. `cilock` looks
  at the command and the repo and figures out which attestors apply.
- **100% traceability** — under eBPF tracing, nothing the build does escapes the
  record (files, execs, and network egress are all captured and hashed).

## Evidence (cross-ecosystem run)

The same flow, on three freshly-cloned projects, no config:

| Project | Lang | `plan` detected (zero-config) | eBPF capture | Egress caught → real registry |
|---|---|---|---|---|
| **rakyll/hey** (this repo) | Go | git, **go-build**, lockfiles | 927 procs, 377 files, 429 execs, 13.7k products | `142.250.x:443` → Google Go module proxy |
| expressjs/express | Node | git, npm-install | 10 procs, 704 files, 2 net | `104.16.3.34:443` → Cloudflare (npm) + DNS |
| psf/requests | Python | git, pip-install | 39 procs, 425 renames, 982 deletes | `151.101.x:443` → Fastly (PyPI) + DNS |

For Go, auto-detection (no `-a` flag) added the real attestors to the signed
envelope on its own: `[lockfiles, environment, git, material, command-run, product, go-build]`.

---

## Part 1 — Local testing (real eBPF)

eBPF is a **Linux kernel** feature. On Linux you can run cilock directly; on
**macOS/Windows** use a Linux VM (cilock hard-errors with *"tracing not supported
on this platform"* otherwise).

### 0. (macOS only) a Linux VM with eBPF

```bash
brew install colima
colima start --cpu 4 --memory 4
colima ssh                       # you're now in the Linux VM; run the rest here
ls -l /sys/kernel/btf/vmlinux    # must exist — CO-RE eBPF needs kernel BTF
```

### 1. Install cilock

The new features (`plan`, `--trace`/eBPF, auto-detect) are on rookery `main`.
Building needs Go 1.26+ (`GOTOOLCHAIN=auto` fetches the right toolchain):

```bash
sudo apt-get update && sudo apt-get install -y golang-go git jq openssl
git clone https://github.com/aflock-ai/rookery
cd rookery && GOTOOLCHAIN=auto go build -o /usr/local/bin/cilock ./cilock/cmd/cilock && cd ..
cilock version
```

### 2. Get this repo + a signing key

```bash
git clone https://github.com/manzil-infinity180/hey && cd hey
openssl genpkey -algorithm ed25519 -out key.pem
```

### 3. Zero config — what does cilock detect?

```bash
cilock plan -- go build -o bin/hey .
```

```
cilock plan — 3 attestor(s) would fire
  fire:
    - git
    - go-build
    - lockfiles
  to run (with tracing): cilock run --trace -a git,go-build,lockfiles -- go build -o bin/hey .
```

No setup, no flags — it read `go.mod` + the argv and told you what applies.

### 4. 100% traceability — wrap the build under eBPF + sign

> **Gotcha (important):** cilock's sandbox confines the traced process to the
> working tree + declared caches. Under `sudo`, `HOME` becomes `/root`, so any
> tool cache there (`~/.cache/go-build`, `~/.npm`, …) gets **EACCES**. Point
> every cache **inside the repo** as below.

```bash
mkdir -p .home .cache
sudo env CILOCK_TRACE_MODE=ebpf \
  HOME="$PWD/.home" \
  GOPATH="$PWD/.home/go" GOCACHE="$PWD/.cache/go" GOMODCACHE="$PWD/.home/go/pkg/mod" \
  cilock run --step build --trace -k key.pem --outfile build.att.json \
  -- go build -o bin/hey .
```

`CILOCK_TRACE_MODE=ebpf` forces the kernel-side path (it errors loudly if eBPF
isn't available, instead of silently falling back to ptrace). You should see
`cilock: tracing mode = eBPF (kernel-side capture)`. No `-a` flag — attestors
are auto-detected.

### 5. Read the signed evidence

A cilock attestation is a **DSSE envelope** — the real statement is base64
inside `.payload`, so decode it first:

```bash
# attestors that ran + the eBPF capture rollup
jq -r .payload build.att.json | base64 -d | jq '{
  attestations: [.predicate.attestations[].type],
  totals: [.predicate.attestations[] | select(.type|test("command-run"))][0].attestation.summary.totals
}'

# every network connection the build made (address + port + syscall)
jq -r .payload build.att.json | base64 -d \
  | jq -r '[.predicate.attestations[] | select(.type|test("command-run"))][0].attestation.processes[]?.network?.connections[]? | "\(.syscall) \(.address):\(.port)"'

# the full process tree (you'll see go, compile, asm, link, gcc, as, ld, git)
jq -r .payload build.att.json | base64 -d \
  | jq -r '[.predicate.attestations[] | select(.type|test("command-run"))][0].attestation.processes[]?.program' | sort -u
```

---

## Part 2 — CI testing (GitHub Actions)

`.github/workflows/supply-chain.yml` wraps a whole Go supply-chain pipeline with
the official [`cilock-action`](https://github.com/aflock-ai/cilock-action) — each
real tool is wrapped by cilock, so each emits its own signed attestation:

| Step | Tool wrapped | Attestor(s) | What it proves |
|---|---|---|---|
| `build` | `go build` | environment, git, github, **secretscan** | attested build (process tree traced); secretscan **records** findings (observe) |
| `govulncheck` | `govulncheck` | …, **sarif** | Go call-graph vulnerability scan (reachability) |
| `gosec` | `gosec` | …, **sarif** | Go SAST findings |
| `sbom` | `syft` | …, **sbom** | CycloneDX SBOM of the built binary |
| `trivy` | `trivy fs` | …, **sarif** | filesystem vulnerability scan |

It also: signs **keyless via Sigstore** (public-good Fulcio + GitHub OIDC — no keys,
no TestifySec account), prints a per-step summary table to the job summary, runs a
**fail-closed policy gate** (the build attestation must carry `command-run` +
`product` + `github`; secretscan findings are reported as informational), and uploads
every attestation as an artifact. Runs on push/PR to `master` and via **Run workflow**.

Why all scanners use the `sarif` attestor: gosec/govulncheck/trivy all emit SARIF,
and `sarif` ships in the action's default binary (the dedicated `trivy`/`govulncheck`
attestors may not). `secretscan` and `sbom` ship too. The action's `cilock-args`
only passes **secretscan** flags through — other `--attestor-*` flags are ignored.

### The release gate

The `policy gate` step is **fail-closed**: it blocks the job unless the build
attestation carries the core evidence (`command-run` + `product` + `github`). To make
it stricter (also fail on secretscan findings, or on high-severity SARIF results), or
to do it properly, replace it with `cilock verify` against a signed Witness policy
(see Part 3 + the `release-promotion-gate` / `verify-in-a-release-gate` docs): a
separate `promote.yml` fetches the attestations and blocks deploy on policy failure.

### A note on secretscan + `--trace`

In the `build` step, secretscan scans the **traced build's materials** — which
include files the Go toolchain/stdlib touched (e.g. `crypto/tls/testdata` PEM keys).
That can surface a finding that has nothing to do with *your* code, which is why this
workflow records (doesn't hard-fail on) secretscan here. For a real fail-closed secret
gate, scope it to your source tree (a Gitleaks allowlist for toolchain/`testdata`
paths) rather than a fully-traced build.

### Tracing in CI is **ptrace**, not eBPF

The `cilock-action` runs the rookery library **in-process** and traces with
**ptrace** — which works on stock GitHub-hosted runners with no special setup.
For real **eBPF** in CI you must run the cilock **binary** directly with
`CAP_BPF`/`CAP_PERFMON`, which means either:

- a **self-hosted runner**, or
- a **container job** with `options: --cap-add=BPF --cap-add=PERFMON`, running
  `sudo cilock run --trace …` instead of the action.

(eBPF on hosted runners is best-effort — Azure-flavored kernels vary; cilock
auto-falls-back to ptrace and records which backend produced the evidence.)

### Signing options

- **Keyless Sigstore (default here)** — each step signs via **public-good Fulcio**
  (`fulcio-url: https://fulcio.sigstore.dev`) using the workflow's GitHub OIDC token
  (`id-token: write`) + a public Sigstore timestamp. No keys to manage, no account.
- **File key** — set `key:` to a PEM path and `enable-sigstore: false` for an
  air-gapped / self-contained signer (what the local guide uses).
- **TestifySec platform (Archivista)** — `enable-archivista` is off here. Once the
  **free tier is bound** (`cilock login`), flip it to `true` to centralize evidence.

---

## Part 3 — Other cilock functionality worth testing

```bash
cilock attestors list           # ~50 attestors compiled in
cilock tools list               # the ~114-tool detection registry behind `plan`
cilock plan -- docker build .   # try other ecosystems — note the provenance warnings
```

- **`cilock verify`** — the release **gate**. Verify the attestation against a
  Witness policy; it exits non-zero when a rule fails (e.g. "must build from a
  tagged ref", "no leaked secrets", "scan must pass"). This turns *evidence*
  into an enforceable gate.
- **`secretscan`** — already in the CI attestors; add
  `cilock-args: "--attestor-secretscan-fail-on-detection"` to fail the build on
  a leaked credential.
- **`sbom` / `slsa`** — add `sbom` to the attestor list (and
  `attestor-sbom-export: true`) to emit an SBOM attestation.
- **Platform / free tier** — `cilock login` binds attestations to a tenant; the
  `platform` attestor currently soft-fails with *"not logged in"* until bound.

## Known quirks (as of this testing)

- `npm-install` is **detection-only** (recognized by `plan`, but capture happens
  via the `command-run`/eBPF trace — there's no standalone `npm-install` attestor).
- **The argv you run matters for matching:** `pip install .` auto-fires the
  `pip-install` attestor; `python -m pip install .` doesn't (different argv prefix).
- A few `connect` events have decoded as port `:9` alongside the correct `:443`
  — looks like a sockaddr port-parse artifact in the net-event decoder.

---

*Generated while testing cilock per Cole's "zero configuration, 100% traceability"
goal. Reproduce locally with the steps above, or just push and watch the
`supply-chain` workflow run.*
