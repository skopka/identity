# Releasing

Releases are published from Git tags by `.github/workflows/release.yml`.

## Repository Setup

Create a protected GitHub Actions environment named `release`, restrict it to
version tags and require a reviewer. Configure NuGet.org Trusted Publishing for
the `Skopka` account with repository owner `skopka`, repository `identity`,
workflow `release.yml`, environment `release` and package pattern
`Skopka.Identity*`. The release job exchanges its GitHub OIDC token for a
short-lived NuGet API key; no long-lived `NUGET_API_KEY` secret is needed.

The release workflow publishes:

- `Skopka.Identity.Abstractions`
- `Skopka.Identity.Core`
- `Skopka.Identity.Ef`
- `Skopka.Identity.Ef.PostgreSql`
- `Skopka.Identity.Ef.Sqlite`
- `Skopka.Identity.Infrastructure`
- `Skopka.Identity`

## Documentation

For consumer-visible API, options, defaults, behavior or package changes, update the
package README, relevant documentation and XML comments and the matching Russian and
English Products overview, guides and examples in the same work before release. Build
and verify complete working examples against the supported version. If a change has no
documentation impact, record the explicit reason in the release work.

The public site is https://products.skopka.ru; its repository is
`H:\Rep\skopka\products`. Follow `docs/documentation-workflow.md` there. Prepare the
Products changes before release, but do not publish unreleased API documentation from a
moving `main` branch. After the GitHub tag and the coordinated NuGet package set are published,
verify their availability and update the Identity source pin in
`scripts/fetch-sources.sh` to the release tag and its full commit. Update affected
version mentions in the Products README, `identity/index.md`, `en/identity/index.md`,
`guides/ru/identity.md` and its subpages, `guides/en/identity.md` and its subpages,
and `api-index/identity/index.md`; update the table of contents only when needed.

Run `sh scripts/build.sh` in the Products repository and verify the generated API,
examples and links. Publish the documentation under the existing authorization scope.
If publication is not complete, report the exact remaining stage; writing the changes
alone does not mean they are live. After deployment, verify the live Russian and English
overview, guide and API pages, including README and NuGet links, without Basic Auth.
Include the package version, tag and commit, the Products commit and the live-check
result in the release summary.

## Publish a Release

Start from a verified commit on `main`, then create and push an annotated version tag:

```shell
git switch main
git pull --ff-only
git tag -a v0.19.0 -m "Skopka.Identity 0.19.0"
git push origin v0.19.0
```

The workflow removes the leading `v` and uses the remainder as the assembly and
NuGet package version. The tag's base version must match `VersionPrefix` in
`Directory.Build.props`, use valid SemVer without build metadata and point to a
commit reachable from `origin/main`. It restores, builds, runs the complete
test suite, audits dependencies, verifies the exact seven packages and symbol
packages and restores a standalone consumer from those package files before
publishing.

Before the first immutable write, the workflow proves that this version is absent
for every package ID. It then pushes all seven packages in dependency order without
`--skip-duplicate` and waits until the complete set is public. NuGet.org does not
provide a transaction across package IDs; after a partial publication, never reuse
the version. Fix the cause and publish a new patch version. The GitHub Release is a
separate dependent job and attaches the same `.nupkg` and `.snupkg` files.

Third-party Actions are pinned to reviewed commit SHAs. Dependabot proposes
updates to those pins.

Normal branch pushes and pull requests never publish packages. Their CI artifacts are
temporary GitHub Actions artifacts only.
