# Changelog

All notable changes to **DrogonSec** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`node_modules/` is read when a project commits no lockfile.** Such a
  repository was scanned from `package.json` alone — its declared dependencies,
  at ranges — so everything they pull in was invisible, and the scan reported
  almost nothing while succeeding. The installed tree on disk answers the same
  question a lockfile does, exactly: on a project declaring only
  `express@4.17.1` with its lockfile deleted, 12 vulnerabilities are found
  instead of 2, and the SBOM lists 52 components instead of 1. Sources are tried
  in order — `package-lock.json`, `yarn.lock`, `node_modules/`, `package.json` —
  and none of them touches the network.

- **`yarn.lock` is parsed, in both of its formats** — the bespoke text of Yarn 1
  and the YAML of Yarn 2 and later. A yarn project was previously read from its
  `package.json` alone, so it had the same blind spot npm projects had: on a
  project declaring only `express@4.17.1`, 1 package was visible instead of 52,
  and 2 vulnerabilities instead of 12. Both formats now produce identical
  results to the equivalent `package-lock.json`.
- **A project carrying two lockfiles for one ecosystem is read once.** A
  `package-lock.json` left beside a `yarn.lock` after a migration describes the
  same installation twice; `package-lock.json` wins, deterministically rather
  than by whichever the directory walk reached first.

- **`package-lock.json` is parsed, so npm projects are scanned in full.** The
  SCA engine read `package.json` alone, which lists what a project declared, at
  version ranges. Everything those dependencies pull in — the overwhelming
  majority of installed code, and where most advisories land — was invisible.
  On a project whose only declared dependency is `express@4.17.1`, DrogonSec
  saw 1 package and now sees 50, reporting 12 vulnerabilities where it
  previously reported 2. All three lockfile formats are handled: the nested
  tree of npm 6 and the flat `packages` map of npm 7 and later.
- **Findings say how a package got there.** Every SCA finding now carries
  `direct` and, when it is not direct, `dependency_path` — the chain that
  introduces it, shown in the terminal report as `Required : via express`. A
  vulnerability in a package a project never named is not fixed by upgrading
  that package, and the chain names what has to move instead.
- **Versions are the ones actually installed.** A range like `^4.17.1` is not a
  version and cannot be matched against an advisory; reading the lockfile
  replaces the guess with the resolved version, which removes false positives
  and false negatives at the same time.

### Fixed

- **The same vulnerability could be reported twice.** OSV holds some flaws under
  several identifiers that alias one another — `path-to-regexp` 0.1.7 comes back
  as both `GHSA-37ch-88jc-xwx2` and `GHSA-9wv6-86v2-598j`, each listing the
  other, both resolving to `CVE-2024-45296`. Findings are now collapsed by
  package, version, manifest and CVE, falling back to the advisory identifier
  for advisories that never received a CVE.
- **The documented SCA support was aspirational.** `docs/modules.md` listed
  `yarn.lock`, `Pipfile.lock`, `pyproject.toml`, `go.sum`, Gradle builds,
  `composer.lock`, `Cargo.lock` and the whole .NET ecosystem as supported. None
  of them were parsed. The table now states what the engine reads, how deep it
  goes for each ecosystem, and what is not covered.

### Added

- **Leak findings now carry the column of the secret**, in the JSON output and
  in the SARIF region. Only SAST findings had one, so a reader of a leak had no
  way to tell where on the line the credential sat and could only mark the line
  as a whole — GitHub Code Scanning highlighted from column 1, and an editor
  would underline the variable name along with everything else.

### Fixed

- **Columns are counted in characters rather than bytes.** A line with accented
  text ahead of the match reported a column past where the match really starts,
  because a multi-byte character counted once per byte. SARIF measures columns
  in characters, and so does every editor. This affected the SAST columns that
  already existed.
- **`--severity` was ignored by the leak engine.** SAST and SCA both dropped
  findings below the requested floor; leaks reported every finding regardless,
  so `drogonsec scan . --severity HIGH` still returned LOW secrets. This also
  made the test-aware demotion pointless for leaks — a secret lowered to LOW
  because it sits in a fixture was reported anyway — and filled this project's
  own GitHub Security tab with 30 alerts for the fake credentials that exist to
  exercise the detectors. Leaks are now held to the same floor, in the working
  tree and in `--git-history`.

### Changed

- **Secrets on `.gitignore`d files are demoted to LOW rather than INFO.** The
  demotion exists so a local `.env` stops inflating the CRITICAL count while
  staying visible — a copy committed earlier in history is still a real
  exposure ([#17](https://github.com/filipi86/drogonsec/issues/17)). INFO sits
  below the default `--severity LOW` floor, so once leaks respect that floor an
  INFO finding would have vanished from the default scan instead. LOW keeps the
  finding where the issue intended it.
- **The banner, progress bars, scan summary and warnings now go to stderr**,
  leaving stdout for what the caller asked for: the findings report, the shell
  completion script, the `version` and `rules list` output. `drogonsec scan .
  --format json > report.json` previously wrote 58 lines of ASCII banner into
  the file ahead of the JSON, so the result parsed as nothing at all; the same
  applied to `sarif` and `cyclonedx`, and to any pipe. Nothing is hidden by
  this — stderr goes to the terminal, so an interactive run looks exactly as it
  did.

### Security

- **`golang.org/x/crypto` moves to v0.56.0.** Two advisories in
  `golang.org/x/crypto/ssh` — `GO-2026-6354` and `GO-2026-6355`, both denial of
  service on a deadlocked channel — are reachable from `monitor.shallowClone`,
  which calls `git.PlainClone` and through it `ssh.NewClientConn`. Both are
  fixed in v0.56.0. As with the Go 1.26.6 bump below, `govulncheck` had started
  failing the build on `main` as the advisories were published, without any
  change to the source. The dependency is indirect, via go-git, so only the
  version pin moves; `golang.org/x/text` follows to v0.41.0 as a transitive
  requirement.

- **The build moves to Go 1.26.6**, in CI, in the Docker image and as the floor
  in `go.mod`. Five advisories in the standard library — `net/http`,
  `crypto/tls`, `net/url` and `encoding/asn1` — are reachable from the monitor's
  HTTP client, the webhook server and the SCA client, and all five are fixed in
  1.26.6. `govulncheck` reports zero affecting the code after the bump; it had
  started failing the build on `main` as the advisories were published, without
  any change to the source.

## [0.3.0] - 2026-08-13

Correctness release for the SCA engine. Writing the first tests for it turned
into an audit: dependencies of two ecosystems were never checked at all,
advisories could be attributed to the wrong package, and the findings that did
come back were missing every field needed to act on them. Findings are now also
ordered by severity in every output.

### Added

- **Findings are ordered by severity**, CRITICAL first and INFO last, in every
  output: the terminal report, JSON, SARIF and HTML. Within a severity the
  highest CVSS comes first, then the file and line, so two scans of unchanged
  code produce identical reports and a diff between scans shows real changes
  rather than reordering.
- **`linux/arm64` release binary**, matching the platforms the Docker images
  already covered.

### Fixed

- **SCA findings carried no CVE, description, severity or fix.** OSV's
  `/v1/querybatch` answers with identifiers only — each vulnerability is
  `{id, modified}` and nothing more — so every field that makes a finding
  actionable was empty: the OSV id stood in for the CVE, there was no
  description, the severity defaulted uniformly to HIGH with a CVSS of 0, and
  there was no version to upgrade to. Each advisory's full record is now
  fetched from `/v1/vulns/{id}`, once per advisory and with bounded
  concurrency; an advisory whose details cannot be fetched is still reported.
- **The suggested upgrade could be a downgrade.** An advisory patches several
  release branches at once — CVE-2022-28346 lists 2.2.28, 3.2.13 and 4.0.4 —
  and the first one in the list was taken, so a project on Django 3.2.12 was
  told to "upgrade" to 2.2.28. The lowest fix that is actually ahead of the
  installed version is chosen, keeping the advice on the project's own branch
  when that branch has a fix.
- **SCA findings never reached SARIF**, and therefore never reached GitHub
  Code Scanning, even though the text, JSON and HTML reporters all included
  them.
- **SCA missed every Python and PHP dependency.** The manifest parsers label
  them `pypi` and `packagist`, but the OSV client only recognised `pip` and
  `composer`, so those dependencies were dropped from the query without a
  warning and no advisory was ever reported for either ecosystem.
- **SCA could attribute a vulnerability to the wrong package.** Dependencies
  whose ecosystem OSV does not cover are skipped when the batch request is
  built, but the responses were indexed back into the original list, shifting
  every result past the first skipped dependency onto a different package.
- **`Gemfile.lock` produced phantom dependencies.** Every parenthesised line was
  read as a resolved gem, so the `DEPENDENCIES` section and each gem's own
  requirements were parsed as versions like `~>` or `=`. Only the `specs:`
  listing is read now.
- **`requirements.txt` versions kept their environment markers and comments**:
  `requests==2.31.0 ; python_version < "3.12"` yielded the whole trailing string
  as the version, which matches no advisory.
- **`ScanLine` did not apply the entropy gate** the file and git-history
  scanners applied, so it reported matches a real scan discards. The three
  scanners now share one matcher and cannot drift apart again.

### Security

- **The monitor no longer writes its access token to disk.** The clone URL
  embedded the token as userinfo (`https://oauth2:TOKEN@host/repo.git`), and git
  records the remote URL in the clone's `.git/config` — so every monitored scan
  wrote the token in plaintext into its temporary workspace, where it outlived
  the scan if the process was killed before cleanup. The token is now passed to
  go-git out of band and the URL carries no credentials.

### Changed

- **Secrets in commented-out lines are now reported**, at the rule's own
  severity. The detector skipped every line starting with `#`, which is the
  comment marker in `.env` files, YAML, and Dockerfiles — exactly where
  credentials get commented out instead of rotated. A credential in a committed
  file is committed whether or not a `#` precedes it. The entropy gate and
  placeholder suppression still apply, so documentation samples are unaffected.
- **Version is defined in one place** (`internal/version`), injected at link
  time and recovered from the embedded build information when it is not. It was
  previously duplicated across the banner, the `version` command, the scan
  report metadata, the Makefile and the CI build, and the `version` command
  reported a hardcoded build date and Go version that had gone stale.

## [0.2.0] - 2026-08-13

Precision release. The SAST engine went through an empirically-audited pass
against real open-source projects to cut false positives without trading them
for false negatives, six languages gained rule coverage, and the supply chain
of the build itself was hardened.

### Added

- **CycloneDX SBOM export** (`--format cyclonedx`): emits a CycloneDX 1.5 JSON
  Software Bill of Materials of the dependencies discovered by the SCA engine,
  with Package URLs (purls) per ecosystem (npm, pypi, golang, maven, gem,
  composer, pub). Flat component inventory, deduplicated and consumable by
  Grype, Trivy, and Dependency-Track. Transitive graph and SPDX output are
  planned for a later release. ([#31](https://github.com/filipi86/drogonsec/issues/31))
- **SAST coverage for 6 new languages**: Elixir (`EX-*`), C/C++ (`C-*`),
  Swift (`SW-*`), Dart (`DART-*`), Erlang (`ERL-*`), and Nginx (`NGINX-*`),
  plus `TF-006` for IAM wildcard policies in Terraform. 124 rules total.
- **File-scoped rules** (`FileScoped` + `RequiredPattern`): a rule mechanism for
  whole-file "security control is absent" checks, which line-scoped patterns
  cannot express.
- **Multi-platform Docker images**: `linux/amd64` and `linux/arm64`
  ([#42](https://github.com/filipi86/drogonsec/pull/42)).

### Changed

- **False-positive reduction**, validated against a true-positive corpus and
  real projects (okhttp, express, cartography, redis, caddy, vapor, flutter,
  cowboy, phoenix): `KT-003` now matches real trust-all idioms instead of bare
  API names (-757 false positives on okhttp); `JS-011`, `JS-016` and `HTML-002`
  were rebuilt as file-scoped missing-control checks at LOW; `PY-003`, `PY-010`,
  `PY-011`, `PY-019`, `PHP-006`, `JS-004`, `GEN-001`, `CS-004` and `GO-007`
  gained context-aware patterns and placeholder suppression.
- **False-negative recovery**: `PY-011` catches secret logging via `+`
  concatenation; `JS-004` and `PHP-006` no longer suppress real secrets and weak
  default credentials; `PY-021`, `PY-022` and `GO-009` surface cross-line weak
  RNG and variable URL SSRF at LOW instead of dropping them.
- **Test-aware severity demotion**: hardcoded secrets under test paths report as
  LOW and control checks as INFO — demoted, never silently dropped. Findings are
  only dropped when a pattern is provably non-vulnerable.
- **Reproducible CI toolchain**: all GitHub Actions pinned to commit SHAs and
  `golangci-lint` pinned to v2.12.2.

### Removed

- **Rule `GEN-002`**: it flagged public X.509 certificates as private keys, a
  false positive with no true-positive case to justify it.

### Fixed

- CLA workflow: signatures are stored on a dedicated unprotected branch, rechecks
  can re-run, the `reopened` trigger is handled, and the skip is keyed on the PR
  author rather than the event actor.
- The dogfooding security scan now exits cleanly instead of failing the pipeline
  on its own report.
- The staging pipeline has the `packages:write` permission needed to push to GHCR
  ([#39](https://github.com/filipi86/drogonsec/pull/39)).

### Security

- **Go 1.26.5**, patching `GO-2026-5856` in `crypto/tls`.
- Staging Docker publishing is gated to branch pushes: on `pull_request` it
  published `:staging` images to GHCR before any review.

## [0.1.0] - 2026-06-23

First public release of DrogonSec, a high-performance open-source security
scanner combining SAST, SCA, secret detection, and IaC analysis in a single
binary, built for developers and CI/CD pipelines.

### Added

- **SAST engine**: static analysis with language-specific rule sets for 20+
  languages, aligned with the OWASP Top 10:2025.
- **SCA engine**: dependency vulnerability scanning against the OSV database,
  with manifest parsers for npm, pip, Go, Maven, Ruby, Composer, and Dart.
- **Secret detection**: regex and Shannon-entropy based leak detection over the
  working tree and full git history, with per-rule confidence levels and
  match redaction.
- **IaC analysis**: misconfiguration checks for infrastructure-as-code.
- **AI-powered remediation**: optional remediation suggestions via local Ollama
  (no API key) or cloud providers (Anthropic, OpenAI-compatible, custom
  endpoints), enabled with `--enable-ai`.
- **Output formats**: human-readable text, JSON, native SARIF for GitHub Code
  Scanning, and a standalone HTML report.
- **Branch monitoring**: webhook server for scanning repositories on push.
- **CLI**: `scan` command with per-engine toggles, severity filtering, and
  shell completion for bash and zsh.
- **CI/CD**: GitHub Actions pipeline with build, test, lint, govulncheck, and a
  self-scan security gate.

[Unreleased]: https://github.com/filipi86/drogonsec/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/filipi86/drogonsec/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/filipi86/drogonsec/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/filipi86/drogonsec/releases/tag/v0.1.0
