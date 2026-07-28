# Security Policy

## Supported Versions

Skopka.Identity is pre-1.0. Security fixes are provided only for the latest published
0.x release and the current default branch.

## Reporting a Vulnerability

Do not report suspected vulnerabilities in a public issue, discussion or pull request.

Use the repository's **Security** tab and GitHub private vulnerability reporting:

<https://github.com/skopka/identity/security/advisories/new>

Include:

- affected package and version or commit;
- required configuration and deployment assumptions;
- reproducible steps or a minimal proof of concept;
- expected and observed security impact;
- suggested mitigation, if known.

Do not include real credentials, tokens, user data or production connection strings.

The maintainers will acknowledge the report, validate the affected surface and coordinate
disclosure. No fixed response SLA is promised while the project remains pre-1.0.

## Scope

Reports are especially useful for:

- password verifier or pepper handling;
- token forgery, replay or purpose confusion;
- session rotation and revocation bypass;
- user enumeration and rate-limit bypass;
- authorization boundary confusion in roles or step-up;
- persistence constraint or optimistic concurrency bypass;
- secret exposure through errors, logs or serialized models.

Application endpoint authorization, TLS termination, secret-manager configuration and
delivery-channel security are owned by the consuming application, but reports showing an
unsafe library default are still in scope.
