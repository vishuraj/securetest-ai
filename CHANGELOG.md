# Changelog

All notable changes are documented here. The project follows [Semantic Versioning](https://semver.org/).

## [1.0.1] - unreleased

* Spring Boot 4.0 and 4.1 support. 1.0.0 failed to start on Boot 4 (a Boot class it used moved package) and rejected
  some dashboard requests under Jackson 3.
* WebFlux apps on Spring Boot 3.0 and 3.1 now start.
* Tested on every build against a fresh app on each Spring Boot line from 3.0 to 4.1, with Spring MVC and WebFlux, both
  with Spring Security (`compatibility/`).
* Releases: every merge into `master` uploads the current version to the Central Portal.
* Microservices: add the dependency once in the parent POM. Spring Cloud infrastructure apps (Config Server, Eureka,
  Gateway, Spring Boot Admin) are detected and skip the source-code modules (`securetest.role`).
* **All services** page: shown automatically in a microservice system and never in a monolith. Services are found
  through Spring Cloud service discovery or `securetest.fleet.members`, and each row shows health, performance, release
  gate, findings and module states. **Open** drills into that service's own dashboard through the same URL and sign-in.
  Services trust each other through `SECURETEST_FLEET_TOKEN`.
* Fix: health showed UNKNOWN when the Actuator jar was present without its health endpoint.
* Fix: a stray "null" next to the signed-in user's name.
* Safe to ship in production: every module is off by default (Health included) and nothing runs in the background until
  SecureTest is used (no flush loop, lazy housekeeping).
* Findings workflow: Retest (scanner findings re-run their scanner; verified fixed / still present), findings reported by
  testers, comments, evidence attachments, and Jira / GitHub issues.
* Pentest / VAPT module: engagements, methodology checklists (OWASP WSTG categories, API Top 10 2023, MASVS v2, network),
  retest phase, engagement report and completion letter.
* Attack Surface module: asset register, subdomain discovery (opt-in certificate logs), HTTPS / certificate / banner /
  exposed-tool checks, daily monitoring, alerts for new hosts, expiring certificates and new high/critical CVEs.
* AI / LLM Security module (OWASP Top 10 for LLM Applications): a code check and an active prompt-injection test.
* Security assistant: AI chat about the findings (opt-in, redacted, shares the AI budget).
* Vulnerability disclosure program (opt-in): security.txt, a public report form and a triage queue.
* Agency workspace: clients and per-client tokens in the All services view, and a portfolio report.
* Release readiness: live checks, waivers, checklist, role-based sign-off and a release report.

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
