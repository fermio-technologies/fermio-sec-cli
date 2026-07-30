# Security policy

## Supported versions

Security fixes are currently applied to the latest release candidate and the `main` branch.

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue. Use GitHub private vulnerability reporting for this repository when available, or contact Fermio Technologies through an established private security channel.

Include:

- affected version or commit;
- operating system and target architecture;
- minimal reproduction steps;
- expected and observed behavior;
- security impact;
- whether the report involves source disclosure, unsafe file handling, rulepack parsing or CI/release integrity.

Do not include real secrets, customer source code or personal data in the report. Use synthetic fixtures whenever possible.

## Scanner trust boundary

Fermio treats scanned repositories, PHP source files, Composer manifests, configuration files, ignore files and rulepacks as untrusted input.

The scanner must not:

- execute PHP or Composer scripts;
- follow symbolic links by default;
- load native or executable rule plugins;
- require network access for a local scan;
- print detected secret values in clear text;
- include source snippets or runtime values in baseline files.

Release archives are accompanied by SHA-256 checksums. Verify downloaded archives before installation.
