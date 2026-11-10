# Changelog

All notable changes are documented here. The project follows [Semantic Versioning](https://semver.org/).

## [1.0.1] - unreleased

* Spring Boot 4.0 and 4.1 support. 1.0.0 failed to start on Boot 4 (a Boot class it used moved package) and rejected
  some dashboard requests under Jackson 3.
* WebFlux apps on Spring Boot 3.0 and 3.1 now start.
* Tested on every build against a fresh app on each Spring Boot line from 3.0 to 4.1, with Spring MVC and WebFlux, both
  with Spring Security (`compatibility/`).
* Releases: every merge into `master` uploads the current version to the Central Portal.

## [1.0.0] - 2026-11-10

First public release.

* Works with Spring MVC or WebFlux on Spring Boot 3.2 – 3.5 (MVC also on 3.0 – 3.1), with or without Spring Security,
  in every profile. Local requests go straight in; other machines and production profiles sign in as `admin` with a
  generated password (or your own users, OIDC or Spring Security).
* Spring Boot starter: one dependency adds the SecureTest dashboard at `/securetest`.
* Modules: health, runtime metrics, testing (JUnit/JaCoCo import, OpenAPI tests, Playwright, Selenium/Appium runner,
  manual and exploratory testing), code quality, vulnerability (SBOM, OSV, secrets, Trivy), API security (passive
  checks, active probes, ZAP), performance (load test, JMeter), compliance mapping, network/TLS, runtime alerts,
  cloud/Kubernetes (IaC rules, Checkov, Trivy, Prowler) and migration (Java / Spring Boot / jakarta).
* Findings workflow, governed exceptions, code highlighting, rule-based and opt-in AI-assisted fixes with undo.
* PDF/XLSX/CSV/JSON reports, scheduled scans, webhooks and e-mail, hash-chained audit log, release gate.
* Authentication: local-dev, basic, container and OIDC; role-based access control.
* Control plane and remote worker (applications, not published to Maven Central).
