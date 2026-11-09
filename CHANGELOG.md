# Changelog

All notable changes are documented here. The project follows [Semantic Versioning](https://semver.org/).

## [1.0.0] - unreleased

First public release.

* Spring Boot starter: one dependency adds the SecureTest dashboard at `/securetest`.
* Modules: health, runtime metrics, testing (JUnit/JaCoCo import, OpenAPI tests, Playwright, Selenium/Appium runner,
  manual and exploratory testing), code quality, vulnerability (SBOM, OSV, secrets, Trivy), API security (passive
  checks, active probes, ZAP), performance (load test, JMeter), compliance mapping, network/TLS, runtime alerts,
  cloud/Kubernetes (IaC rules, Checkov, Trivy, Prowler) and migration (Java / Spring Boot / jakarta).
* Findings workflow, governed exceptions, code highlighting, rule-based and opt-in AI-assisted fixes with undo.
* PDF/XLSX/CSV/JSON reports, scheduled scans, webhooks and e-mail, hash-chained audit log, release gate.
* Authentication: local-dev, basic, container and OIDC; role-based access control.
* Control plane and remote worker (applications, not published to Maven Central).
