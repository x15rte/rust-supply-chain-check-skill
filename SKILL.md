---
name: rust-supply-chain-check
description: "Audit a Rust project's dependency tree and build config against supply-chain attacks and the RustSec advisory database; verify cached artifacts on disk, remediate unpatched advisories, and report under local://."
globs:
  - "Cargo.toml"
  - "**/Cargo.toml"
  - "Cargo.lock"
  - "**/Cargo.lock"
---

# Rust Supply-Chain Check

Audit a Rust repository against supply-chain attacks: malicious or typosquatted crates, registry/configuration hijack, unpatched advisories, and unverified third-party binaries. The procedure runs fully offline except for one advisory-database download. A search hit alone is never a finding — verify every claim against the lockfile, the on-disk cache, or a fresh advisory source before reporting it.

## Method

1. **Scope and threat context.** If the user references an alert, advisory, blog post, or issue, read its primary source first and extract: affected crate names and exact versions, the attack vector (build script vs. runtime vs. manifest entry), indicators of compromise (files, hosts, ports), and the patched versions. The malicious-crate list drives every later check — work from the advisory, never from memory.
2. **Lockfile and manifest audit.** Read the workspace `Cargo.toml` and parse `Cargo.lock` (it is TOML) per package: name, version, `source`, `checksum`. Flag: git or path sources, `[patch]`/`[replace]` sections, registry mirrors, custom indices, duplicate versions of the same crate, and any advisory-named crate at an affected version. Confirm the lock matches the manifest with `cargo metadata --locked`; see guardrails for interpreting failures.
3. **On-disk artifact verification.** List the registry cache and extracted sources under `$CARGO_HOME` (`~/.cargo/registry/cache/<index-hash>/` and `registry/src/<index-hash>/`). Confirm only expected versions exist (e.g. an advisory-named crate must be present only at the clean version). Verify checksums: `sha256sum` the cached `.crate` files and compare with the `checksum` field in the lock. Check the advisory's named file IOCs on disk — presence is a finding, absence is evidence but not proof of no prior execution; state exactly what was and was not checked.
4. **Build configuration audit.** Look for registry-redirect attack surface: project and user `.cargo/config.toml` (or `$CARGO_HOME/config.toml`), `replace-with`/`source.<name>.registry` mirrors, `[net]` overrides, and `CARGO_REGISTRIES_*`/`CARGO_SOURCE_*`/`CARGO_HOME`/`CARGO_NET_*` environment variables. The lock's `source` lines must all be the default `registry+https://github.com/rust-lang/crates.io-index` unless a mirror is deliberate. Also inspect the repo's own `build.rs`/build scripts for network/download code (a build script is the standard malicious-crate delivery vehicle).
5. **RustSec advisory-db cross-check.** Download a fresh advisory database snapshot (`https://codeload.github.com/rustsec/advisory-db/tar.gz/refs/heads/main` — tarball, no git clone) and run `scripts/advisory_check.py` from this skill against the lock. It implements Cargo semver-range semantics (see below) and classifies every locked version against `[versions]` `patched`/`unaffected` ranges. Report unpatched advisories as vulnerabilities; report `informational` advisories (unmaintained/unsound) separately — they are warnings, not vulnerabilities.
6. **Remediation and verification.** For each unpatched advisory: back up the lock, run `cargo update -p <crate>` (or `--precise <patched-version>`), then diff the lock to confirm the delta is exactly the intended packages — a manifest resync may legitimately change others, so verify each. Re-run the advisory check to confirm zero unpatched remain, then prove the tree compiles (`cargo check`).
7. **Non-crates.io binaries.** When the project downloads third-party executables, verify the installer or build scripts pin and enforce SHA-256 for every artifact — checksums declared and compared at download and again at staging, hard-failing on mismatch.
8. **Follow-up.** Publish remaining work to the repo's tracker (informational advisory decisions, tooling gaps) as tickets per the repo's issue-tracker conventions, labeled by actionability (`ready-for-agent` for implementable slices, `ready-for-human` for decisions).

## Guardrails — do not flag

- The root workspace package in `Cargo.lock` has no `source` and no `checksum`. That is normal, not a finding.
- Cross-target dependencies (e.g. a Linux-only GTK stack under a Windows-only project) sit in the lock for cross-target resolution but never compile on the supported target. Report them as informational with the "never compiled on this target" note; do not call them vulnerabilities.
- `cargo metadata --locked --offline` failing is usually an offline index-access problem, not proof the lock is stale. Confirm staleness by diffing the lock after `cargo update`; a delta of exactly the intended package proves the manifest was in sync.
- Caret ranges in `Cargo.toml` are normal; the committed lock is the source of truth for builds. Only flag missing/uncommitted locks.
- A crate whose name merely resembles a typosquat is not a finding — compare publisher identity, repository URL, metadata, and whether a build script or manifest change is the injection point.
- Do not claim a payload executed without the advisory's IOCs (files on disk, network evidence). If network history is unverifiable, say so.
- Do not `cargo install` audit tooling as part of the check; use `scripts/advisory_check.py` or the user's existing tooling. `cargo audit` is the standard tool and a fine substitute when installed.
- The advisory snapshot is point-in-time — state its date and that the verdict holds as of that snapshot.

## Cargo semver-range semantics (used by the script)

A requirement string is comma-separated clauses joined with AND. Clause ops: `>=`, `>`, `<=`, `<`, `=`, `^` (bare version = caret: `>= v` and `< next major`, or `< next minor` for `0.x`), `~` (`>= v` and `< next minor`), `*` (any). Prerelease versions sort below the release; numeric prerelease parts sort before alphabetic. A version is vulnerable when it satisfies no `unaffected` range and no `patched` range; empty `patched = []` with no `unaffected` means all versions are affected.

## Report requirements

Write the results to `local://rust-supply-chain-check-report.md` (or a distinct name when the user asks). Include:

```markdown
# Rust Supply-Chain Check

## Scope
- Repository, advisory/threat context, date of advisory-db snapshot
- What was and was not verified (e.g. network history not verifiable)

## Lockfile and manifest audit
- Dependency sources, patch/replace sections, mirror config, duplicate versions

## On-disk verification
- Registry cache contents, checksum comparisons, IOC file check

## Advisory cross-check
- Count of advisories touching the tree; unpatched vs. informational

## Findings
### SUPPLY-001 — concise title
- **Severity:** Critical | High | Medium | Low
- **Affected:** crate @ version, advisory id, patched version
- **Evidence:** lock/cache/config excerpt
- **Impact:** concrete failure mode
- **Action:** remediation taken or recommended

## Informational advisories (not vulnerabilities)
- One line each: crate @ version, advisory id, why acceptable

## Verdict and follow-ups
- Posture per axis; remediation status; tickets published
```

Severity: **Critical** for a confirmed malicious crate/typosquat in the build graph; **High** for an unpatched security advisory with plausible impact on the running app; **Medium** for unpatched advisories of low severity or credible DoS; **Low** for informational-adjacent concerns with a concrete alternative. Use high confidence only after verifying against the lock, cache, or fresh primary source. If the tree is clean, say so plainly with the evidence; never inflate findings.

After writing the report, state its `local://` path and the vulnerable/informational counts without pasting the full report unless asked.
