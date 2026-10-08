# Releasing

One version covers everything: `workspace.package.version` in `Cargo.toml`.
A release is one git tag, `vX.Y.Z`, and ships:

| What | Where | Built by |
|---|---|---|
| `trustgraph-core`, `trustgraph-cli` | crates.io | release-plz ([`release-plz.yml`](../.github/workflows/release-plz.yml), [`release-plz.toml`](../release-plz.toml)) |
| `trust` binaries for Linux (glibc and musl), macOS (x86_64, Arm), Windows (x86_64); shell and PowerShell installers; checksums and build attestations | GitHub Release | dist ([`release.yml`](../.github/workflows/release.yml), generated from [`dist-workspace.toml`](../dist-workspace.toml)) |
| Homebrew formula `trustgraph` | [`trustgraph/homebrew-tap`](https://github.com/trustgraph/homebrew-tap) | dist |
| `@trustgraph/trustgraph` (native, 8 per-platform packages plus the root) and `@trustgraph/trustgraph-wasm` | npm, with provenance | [`npm.yml`](../.github/workflows/npm.yml) |
| CHANGELOG.md, version bump | release PR | release-plz |

`trustgraph-wasm` and `trustgraph-node` are `publish = false` on crates.io;
they ship only through npm. The versions in their `package.json` files are
overwritten from the tag when publishing, so they never need editing.

## Cutting a release

1. Merge work into `master` with [Conventional Commits](https://www.conventionalcommits.org)
   titles (`feat: …`, `fix: …`, `feat!: …` for a breaking change). release-plz
   uses them to pick the next version and write the CHANGELOG. Before 1.0 a
   breaking change bumps the minor version.
2. On every push to `master`, release-plz opens or updates a release PR
   (label `release`) that bumps the version and adds a CHANGELOG entry. Read the CHANGELOG in it, edit it
   if you like, and wait for CI.
3. Merge the release PR. release-plz then publishes `trustgraph-core` and
   `trustgraph-cli` to crates.io and pushes the tag `vX.Y.Z`.
4. The tag starts two workflows:
   - **Release** (dist): builds the seven `trust` archives, the installers and
     the Homebrew formula, creates the GitHub Release with notes from
     CHANGELOG.md, and pushes the formula to the tap.
   - **npm**: builds the native addon for eight targets, smoke-tests it on
     glibc and musl Linux (x86_64 and Arm), macOS and Windows, builds the
     WebAssembly package, and publishes all ten npm packages.
5. Check the [release page](https://github.com/trustgraph/trustgraph-rust-cli/releases),
   [crates.io](https://crates.io/crates/trustgraph-cli) and
   [npm](https://www.npmjs.com/package/@trustgraph/trustgraph).

A version with a suffix (`v1.0.0-rc.1`) is a prerelease: the GitHub Release is
marked as one, Homebrew is skipped, and npm publishes under the `next` tag.

Every publish step skips what is already published, so a release that failed
half way can be re-run from the Actions tab.

### Without release-plz

Bump `workspace.package.version`, commit, then:

```sh
cargo publish -p trustgraph-core -p trustgraph-cli
git tag vX.Y.Z && git push origin vX.Y.Z
```

## One-time setup

None of this exists yet. Until it does, the release workflows skip (release-plz)
or never run (they need a tag); pull requests need no secrets.

1. **Package names.** Confirm `trustgraph-core` / `trustgraph-cli` on crates.io
   and the `@trustgraph` scope on npm (an open question in the
   [roadmap](plan/README.md)). Create the `trustgraph` organization on
   [npmjs.com](https://www.npmjs.com/org/create) to own the scope.

2. **release-plz token** (`RELEASE_PLZ_TOKEN`). Tags and PRs created with the
   default `GITHUB_TOKEN` do not start other workflows, so release-plz needs
   its own token. Create a
   [fine-grained personal access token](https://github.com/settings/personal-access-tokens/new)
   (ideally on a bot account, which becomes the PR author) for
   `trustgraph/trustgraph-rust-cli` with **Contents** and **Pull requests**:
   read and write. Save it as the repository secret `RELEASE_PLZ_TOKEN`
   (Settings → Secrets and variables → Actions). A GitHub App token works too;
   see the [release-plz docs](https://release-plz.dev/docs/github/token).

3. **crates.io.** New crates cannot use trusted publishing, so the first
   release needs a token:
   - Create an [API token](https://crates.io/settings/tokens) with the
     `publish-new` and `publish-update` scopes, limited to `trustgraph-*`, and
     save it as the secret `CARGO_REGISTRY_TOKEN`.
   - After the first release, open each crate's settings on crates.io
     (`trustgraph-core`, `trustgraph-cli`) → Trusted Publishing → add GitHub:
     owner `trustgraph`, repository `trustgraph-rust-cli`, workflow
     `release-plz.yml`. Then delete the `CARGO_REGISTRY_TOKEN` secret and the
     token; release-plz switches to trusted publishing on its own.

4. **Homebrew tap.** Create the public repository
   [`trustgraph/homebrew-tap`](https://github.com/organizations/trustgraph/repositories/new)
   with a README; dist manages `Formula/` in it. Create a fine-grained token
   for that repository with **Contents**: read and write, and save it in this
   repository as `HOMEBREW_TAP_TOKEN`. Without it, the Homebrew job fails and
   dist does not publish the GitHub Release.

5. **npm.** New packages cannot use trusted publishing either:
   - Create a [granular access token](https://www.npmjs.com/settings/~/tokens/granular-access-tokens/new)
     with read and write access to the `@trustgraph` scope (and "bypass
     two-factor authentication" for publishing) and save it as `NPM_TOKEN`.
   - After the first release, for each of the ten packages
     (`@trustgraph/trustgraph`, `@trustgraph/trustgraph-wasm`, and the eight
     `@trustgraph/trustgraph-<platform>` packages) open Settings → Trusted
     Publisher → GitHub Actions: organization `trustgraph`, repository
     `trustgraph-rust-cli`, workflow `npm.yml`. Then delete `NPM_TOKEN` and the
     token, and set each package to "require two-factor authentication and
     disallow tokens". Provenance is published either way.

6. **Optional:** protect `v*` tags and the `master` branch so that only the
   release-plz token (or admins) can create release tags.

When the repository is renamed to `trustgraph/trustgraph`, update the
`repository` URLs in `Cargo.toml` and the `package.json` files, the trusted
publisher settings on crates.io and npm, and the URLs in `install.sh` and
README.md (GitHub redirects the old ones in the meantime).

## Checking the pipeline without publishing

- **Every pull request** runs `dist plan` (the Release workflow), and
  `cargo-deny` and coverage (CI).
- **Pull requests that touch `npm.yml`** or the npm build, and manual runs
  (Actions → npm → Run workflow), build and test every npm package and run
  `pnpm publish --dry-run` for each.
- Locally:

  ```sh
  cargo publish --dry-run -p trustgraph-core -p trustgraph-cli
  dist plan                       # what a release would contain
  dist build --artifacts=all      # archives and installers for this machine, in target/distrib
  cargo deny check
  ```

  Install dist with `cargo install --locked cargo-dist` or from its
  [releases](https://github.com/axodotdev/cargo-dist/releases), at the version
  in `dist-workspace.toml`.

## Changing the release setup

- **dist:** edit `dist-workspace.toml`, then run `dist generate` to rewrite
  `.github/workflows/release.yml`. Never edit `release.yml` by hand: the
  Release workflow fails on pull requests when it is out of date. That is also
  why Dependabot skips it; bump its actions in `[dist.github-action-commits]`.
  To upgrade dist, change `cargo-dist-version` and run `dist generate` with
  that version.
- **Targets:** the `trust` binaries are listed in `dist-workspace.toml`; the
  native npm targets in `crates/trustgraph-node/package.json` (`napi.targets`)
  and the matrix in `npm.yml`.
- **install.sh** is the stable `curl | sh` entry point. It downloads and runs
  `trustgraph-cli-installer.sh` from the release (dist's installer: platform
  detection, checksums, PATH setup) and falls back to building with cargo.
