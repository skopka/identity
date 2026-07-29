# Releasing

Releases are published from Git tags by `.github/workflows/release.yml`.

## Repository Setup

Create a NuGet.org API key that can publish all six `Skopka.Identity` package IDs and
store it in the GitHub repository Actions secret named `NUGET_API_KEY`.

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
git tag -a v0.1.0 -m "Skopka.Identity 0.1.0"
git push origin v0.1.0
```

The workflow removes the leading `v` and uses the remainder as the assembly and NuGet
package version. It restores, builds, runs the complete test suite, audits dependencies
and verifies that all six packages and symbol packages were produced before publishing.

Packages are pushed to NuGet.org. The same `.nupkg` and `.snupkg` files are attached to
the generated GitHub Release. `--skip-duplicate` makes a repeated workflow run safe
after a partial publication.

Normal branch pushes and pull requests never publish packages. Their CI artifacts are
temporary GitHub Actions artifacts only.
