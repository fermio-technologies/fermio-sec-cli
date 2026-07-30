# Fermio Sec CLI release process

## Release candidate gate

A release tag may be created only after all of the following are true:

- the CI workflow completed formatting, Clippy, unit, documentation and end-to-end tests;
- the 250-file performance smoke test stayed within its release budget;
- vulnerable fixtures emitted their expected rule identifiers;
- the safe fixture emitted no findings;
- file-count and file-size limit regressions passed;
- the workspace version and changelog entry match the intended tag;
- the rulepack and configuration schema versions are documented;
- no unresolved high-impact review comments remain;
- the release diff contains no source, credentials, generated reports or private fixtures.

## Create a release candidate

The workspace currently targets `v0.1.0-rc.1`.

```bash
git switch main
git pull --ff-only
git tag -a v0.1.0-rc.1 -m "fermio-sec-cli v0.1.0-rc.1"
git push origin v0.1.0-rc.1
```

Pushing a `v*` tag triggers `.github/workflows/release.yml`.

## Release workflow

The workflow:

1. generates one dependency lockfile;
2. shares that lockfile across every build target;
3. builds Linux x86_64, Windows x86_64, macOS Intel and macOS Apple Silicon binaries;
4. packages the executable with release documentation and the Apache-2.0 license;
5. creates SHA-256 checksum files;
6. publishes the dependency lockfile and its checksum;
7. creates the GitHub release from the existing tag.

## Post-publication verification

- download every archive from the release page;
- verify each `.sha256` file;
- confirm `fermio-sec --version` reports the tagged release candidate;
- scan the committed safe and vulnerable fixtures using at least Linux and Windows artifacts;
- confirm SARIF output imports successfully into a compatible code-scanning viewer;
- record release-specific defects under the `Unreleased` changelog section.

## Rollback

Do not replace files attached to an existing release tag. When an artifact or dependency issue is discovered, mark the release as a pre-release or withdraw it, fix the problem on `main`, increment the release-candidate suffix and publish a new immutable tag.
