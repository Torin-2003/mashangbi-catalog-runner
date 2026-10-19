# Quanshangbi Catalog Runner

This repository contains only a small loader, the workflow and dependency manifests. It contains no business logic, website authentication, payment server, database backups or credentials.

`loader.mjs` obtains a read-only installation token for the separate private state repository, downloads the encrypted runner code file `runner/runner.enc` from that repository, verifies it against the pinned `CATALOG_RUNNER_CODE_SHA256` variable, decrypts it inside the job and executes it. Changing the runner version means committing a new encrypted file and updating the pinned hash.

The runner restores an authenticated encrypted checkpoint from a separate private repository, collects at most ten assigned sources with concurrency two, computes locally, publishes public assets, verifies them, then commits the new generation. It never automatically exports production D1 or falls back to Cloudflare collection. A failed run retains the last committed generation.

## Activation

The workflow is disabled until repository variable `CATALOG_RUNNER_ENABLED` is `1`. Do not enable it until migrations, bootstrap reconciliation, protected private readers and production acceptance have passed. Publishing this repository alone does not complete the migration.

Provision the variables and secrets named in `.github/workflows/catalog.yml`. `CATALOG_CHECKPOINT_KEY` is a 32-byte key encoded as 64 hexadecimal characters. The GitHub App must be installed only on the private state repository, with contents access. The asset deployment token must be scoped for the approved Cloudflare account and must not be a personal CLI/OAuth token. An empty proxy configuration means direct transport only; unknown requested proxy groups fail closed.

Before publishing this generated package, create and review its dependency lockfile with `npm install --package-lock-only --ignore-scripts`. The workflow installs the locked dependencies without lifecycle scripts. Never add production secrets to test branches or untrusted workflows.

## Operations

The off-minute schedule is every fifteen minutes, not a timing guarantee. Each run has a fixed thirty-minute deadline. Scheduling and install overhead have a separate five-minute allowance. Runs do not overlap. Public files contain only the public projection; private SQLite and encrypted checkpoints stay in an isolated temporary directory and are never uploaded as public workflow artifacts.

The final stdout record contains only status, generation and counts, never raw source responses. Investigate safe failure codes and the metered control ledger in the existing administrator interface. Do not resume the paused legacy full-backfill task to recover a failed runner.
