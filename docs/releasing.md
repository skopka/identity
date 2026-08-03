# Releasing

Releases are published from Git tags by `.github/workflows/release.yml`.

## Repository Setup

Create a protected GitHub Actions environment named `release`, restrict it to
version tags and require a reviewer. Create a NuGet.org API key that can publish
all six `Skopka.Identity` package IDs and store it as the environment secret
named `NUGET_API_KEY`.

The release workflow publishes:

- `Skopka.Identity.Abstractions`
- `Skopka.Identity.Core`
- `Skopka.Identity.Ef`
- `Skopka.Identity.Ef.PostgreSql`
- `Skopka.Identity.Infrastructure`
- `Skopka.Identity`

## Publish a Release

Start from a verified commit on `main`, then create and push an annotated version tag:

```shell
git switch main
git pull --ff-only
git tag -a v0.8.0 -m "Skopka.Identity 0.8.0"
git push origin v0.8.0
```

The workflow removes the leading `v` and uses the remainder as the assembly and
NuGet package version. The tag's base version must match `VersionPrefix` in
`Directory.Build.props`, use valid SemVer without build metadata and point to a
commit reachable from `origin/main`. It restores, builds, runs the complete
test suite, audits dependencies, verifies the exact six packages and symbol
packages and restores a standalone consumer from those package files before
publishing.

Before the first immutable write, the workflow proves that this version is absent
for every package ID. It then pushes all six packages in dependency order without
`--skip-duplicate` and waits until the complete set is public. NuGet.org does not
provide a transaction across package IDs; after a partial publication, never reuse
the version. Fix the cause and publish a new patch version. The GitHub Release is a
separate dependent job and attaches the same `.nupkg` and `.snupkg` files.

Third-party Actions are pinned to reviewed commit SHAs. Dependabot proposes
updates to those pins.

Normal branch pushes and pull requests never publish packages. Their CI artifacts are
temporary GitHub Actions artifacts only.
