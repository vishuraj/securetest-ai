# SecureTest AI — embedded Spring Boot starter

[![Build and test](https://github.com/vishuraj/securetest-ai/actions/workflows/build.yml/badge.svg)](https://github.com/vishuraj/securetest-ai/actions/workflows/build.yml)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.vishuraj/securetest-spring-boot-starter)](https://central.sonatype.com/artifact/io.github.vishuraj/securetest-spring-boot-starter)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Add one dependency to a Spring Boot (Spring MVC) application and open **`http://localhost:8080/securetest`**.
You get the same kind of zero-wiring experience as `springdoc-openapi-starter-webmvc-ui`, but with a dashboard for health and
telemetry, testing, code quality, vulnerabilities, API security, performance, compliance, network, cloud/Kubernetes,
runtime alerts, reports, remediation and migration (SRS v1.0, embedded profile).

Maven:

```xml
<dependency>
  <groupId>io.github.vishuraj</groupId>
  <artifactId>securetest-spring-boot-starter</artifactId>
  <version>1.0.0</version>
</dependency>
```

Gradle:

```groovy
implementation "io.github.vishuraj:securetest-spring-boot-starter:1.0.0"
```

That is all: start the app and open `/securetest`. Every optional module starts disabled; you switch modules on and give
targets, credentials and permissions in the dashboard or in `application.yml`. To align several SecureTest modules, import
`io.github.vishuraj:securetest-bom` instead of repeating the version.

Requirements: Java 17+ and Spring Boot 3.2–3.5 (servlet stack). Spring Boot 4 starts with a compatibility warning. A WebFlux app logs a warning and nothing is registered.

## Build and try it

No Maven installation needed: the Maven Wrapper downloads Maven 3.9.16 on first use (`mvnw.cmd` on Windows, `./mvnw` elsewhere).

```bash
./mvnw install
java -jar securetest-sample-app/target/securetest-sample-app-1.0.0.jar --securetest.workspace.source-root=securetest-sample-app
```

Then open http://localhost:8080/securetest. The sample app contains deliberate weaknesses: MD5, `new Random()`, a committed fake
AWS key, a privileged Kubernetes pod, an `openjdk:8` Dockerfile and a legacy Spring Boot 2.7 / `javax` module. Every module therefore
has something to find, and the migration workflow has something to migrate.

## Modules

| Module | Built-in, in-process (safe) | Adapters (installed tools / remote services) |
|---|---|---|
| Health | Actuator health status (status only), JVM snapshot | — |
| Runtime Metrics | CPU, heap/non-heap, pools, GC, threads, classes, FDs, HTTP rate/errors/p50-p99, history, threshold alerts, Prometheus text | Micrometer custom meters |
| Testing | JUnit/TestNG XML + JaCoCo import, flaky detection, OpenAPI contract & auth tests, manual test cases, exploratory sessions, device/browser matrix | Test command runner (`mvn`, `gradle`, Selenium and Appium suites, allowlisted), Playwright browser matrix with failure screenshots |
| Code Quality | Java rules (crypto, injection, CSRF, CORS, TLS, deserialization, XXE, logging), complexity, duplication | SonarQube / SonarCloud |
| Vulnerability | Classpath inventory, CycloneDX SBOM, licenses, EOL frameworks, secrets, OSV (online opt-in or offline feed) | Trivy |
| API Security | Headers, cookies, CORS, version disclosure, exposed Actuator/.git/.env/H2, error leakage; active probes (SQLi, XSS, traversal, rate limiting) | OWASP ZAP |
| Performance | Bounded load test with percentiles, CPU/heap correlation, gates, baseline comparison | Apache JMeter |
| Compliance | Configuration posture + mapping to OWASP Top 10, ASVS, CIS, ISO 27001, SOC 2, GDPR, PCI DSS; evidence pack | — |
| Network / System | TLS/certificate posture, port exposure (active) | — |
| Advanced Security | Falco / Wazuh / SIEM import, sensor health, webhook ingestion | — |
| Cloud / Kubernetes | Dockerfile, Kubernetes/Helm, Compose, Terraform rules | Checkov, Trivy (image/config), Prowler (AWS/Azure/GCP) |
| Migration | Discover → assess → plan → per-file diff → apply → validate → commit/undo (Java 17/21/25, Boot 3.5/4.1, javax→jakarta, Spring Security 6, property renames, wrappers, images) | — |

Cross-cutting: findings with a normalized priority and the preserved source severity ("why this priority?"), dedupe by fingerprint, regression
detection, governed exceptions (reason, owner, expiry, approver), code highlighting that detects stale files, rule-based fixes as diff-first
change sets with a rollback point and undo with conflict detection, opt-in AI-assisted fixes (Claude), PDF/XLSX/CSV/JSON reports, scheduled scans,
saved profiles, a hash-chained audit log, webhooks (Slack/Teams/generic) and e-mail, a release gate (`GET /securetest/api/v1/gate`) and an OpenAPI document for its own API.

You can add your own scanner by declaring a `@Bean` that implements `com.securetest.core.spi.Scanner`. Your own fix provider is a `@Bean` that implements `FixProvider`.

## Security model (secure by default)

* **Dashboard**: on in non-production profiles and **off when a `prod`/`production` profile is active**, unless you set `securetest.dashboard.enabled=true`.
* **Loopback only** by default (`bind-address: 127.0.0.1`). Remote clients get 403.
* **Authentication** (`securetest.dashboard.authentication.provider`):
  * `local-dev` (default): loopback clients act as a local admin.
  * `basic`: users with `{sha256}`/`{env}`/secret-reference passwords.
  * `container`: uses your Spring Security / OIDC principal. Roles come from `SECURETEST_<ROLE>` authorities or `role-mapping`.
  * `oidc`: SecureTest's own single sign-on (Keycloak, Entra ID, Okta, Auth0...). Authorization code + PKCE, ID-token signature checked against the provider's JWKS, roles from a token claim through `role-mapping`, HttpOnly session cookie.
* **RBAC** is enforced on every API call. Roles: VIEWER, DEVELOPER, QA, SECURITY, DEVOPS, OWNER, ADMIN. Permissions: VIEW, CONFIGURE, EXECUTE, APPROVE, REMEDIATE, ADMIN, AUDIT.
* **CSRF**: mutating calls need the `X-SecureTest-Request: 1` header and a same-origin `Origin`.
* **Headers and rate limiting**: strict CSP and security headers, plus a per-client API rate limit.
* **Modules**: every module except Health is **OFF**. Toggles can be locked by policy (`securetest.modules.<id>.locked=true`).
* **Scan targets**: every network target must match `securetest.security.target-allowlist` (`self`, hosts, `*.domain`, CIDR). Cloud-metadata IPs are always refused.
* **Scan confirmation**: active and resource-intensive scans need explicit confirmation. Active scans also need an approver with separation of duties.
* **External tools** run only when listed in `securetest.execution.allowed-commands`. They run in a separate process with a timeout and bounded output.
* **Credentials**: use secret references (`env://`, `prop://`, `file://`, `secret://`). Values are masked, never echoed back, never persisted, and redacted from evidence and reports.
* **Source changes**: these need `securetest.security.allow-auto-remediation=true`. Security-sensitive changes and migrations need APPROVE. SecureTest never applies them under a production profile, never overwrites uncommitted work, always takes a backup first and can undo with conflict detection.
* **AI is opt-in**: rule-based fixes never send code anywhere. AI-assisted fixes need both `securetest.ai.enabled` and `securetest.ai.data-processing-approved`, run only when a user asks for one finding, send a small redacted code window, are validated (range, secrets, bracket balance), carry provider/model/prompt provenance, and always need an approver to apply.

### Using it alongside Spring Security

If your app uses Spring Security, add the dashboard path to your filter chain. Otherwise your app's login or CSRF rules will block it:

```java
http.authorizeHttpRequests(a -> a.requestMatchers("/securetest/**").hasRole("SECURETEST_ADMIN") /* or permitAll() with provider=local-dev */)
    .csrf(c -> c.ignoringRequestMatchers("/securetest/api/**")); // SecureTest applies its own CSRF defence
```

## Configuration reference (all optional)

```yaml
securetest:
  enabled: true
  mode: embedded                    # embedded | connected
  dashboard:
    enabled: true                   # unset = on, except under prod profiles
    path: /securetest
    bind-address: 127.0.0.1         # 0.0.0.0 only with basic/container auth + TLS
    authentication:
      provider: local-dev           # local-dev | basic | container | oidc
      users:
        - { username: alice, password: "{env}SECURETEST_ALICE_PW", roles: [SECURITY] }
      role-mapping: { ROLE_ADMIN: ADMIN, ROLE_QA: QA, sec-team: SECURITY }   # host roles or OIDC claim values
      oidc:                         # used when provider=oidc
        issuer-uri: https://login.example.com/realms/acme
        client-id: securetest
        client-secret-ref: env://SECURETEST_OIDC_SECRET   # omit for public clients (PKCE)
        roles-claim: realm_access.roles                   # dot path into the ID token
        default-role: VIEWER                              # unset = deny unmapped users
        session-timeout: 8h
  control-plane:
    enabled: false
    url: https://securetest.example.com
    enrollment-token-ref: env://SECURETEST_ENROLLMENT
  modules:
    metrics: { enabled: false }
    code-quality: { enabled: true, locked: true }   # policy lock
    performance: { allow-embedded-load-generation: false, max-concurrency: 50 }
  execution:
    max-concurrent-jobs: 2
    job-timeout: 30m
    allowed-commands: [trivy, checkov, jmeter, mvn, npx]   # npx = Playwright
    validation-command: [mvn, -B, -q, verify]
  data:
    storage-dir: ${user.home}/.securetest/${spring.application.name}
    retention: { findings: 365d, jobs: 365d, reports: 180d, audit: 730d }
  security:
    target-allowlist: [self, "*.staging.example.com", 10.20.0.0/16]
    enforce-target-allowlist: true
    require-approval-for-active-scans: true
    allow-auto-remediation: false
    allow-external-intelligence: false    # OSV online lookups
    ingest-token-ref: env://SECURETEST_INGEST_TOKEN
  workspace:
    source-root: .                  # default: working dir when it holds a build file
    repository-url: https://github.com/acme/shop
    ide-link-template: "idea://open?file={absPath}&line={line}"
  telemetry: { sample-interval: 15s, history-size: 240, cpu-alert-threshold: 90, heap-alert-threshold: 90 }
  reports: { organization: ACME, classification: CONFIDENTIAL, timezone: Europe/Berlin }
  notifications:
    webhooks:
      - { name: secops, url: env://SLACK_WEBHOOK, format: slack, events: [finding.critical, scan.failed, approval.required] }
    email:                          # uses your spring.mail.* (spring-boot-starter-mail)
      enabled: false
      from: securetest@acme.com
      to: [secops@acme.com]
      events: [finding.critical, scan.failed, approval.required, alert.threshold]
  ai:                               # opt-in AI-assisted remediation
    enabled: false
    data-processing-approved: false # explicit approval to send redacted snippets to the provider
    provider: anthropic
    model: claude-opus-5-5
    effort: high
    api-key-ref: env://ANTHROPIC_API_KEY
    context-lines: 40
    daily-request-limit: 50
    refusal-fallback: true          # server-side fallback (beta) if a safety classifier declines
  policy: { fail-on: HIGH, max-critical: 0, max-high: 0, max-suppression-days: 365 }
  application: { environment: staging, criticality: high }
```

CI release gate:

```bash
curl -fsS http://localhost:8080/securetest/api/v1/gate | grep -q '"status":"PASS"'
```

## Project layout (SRS 4.2)

| Module | Purpose |
|---|---|
| `securetest-bom` | Version alignment |
| `securetest-core` | Domain model, finding taxonomy, scanner/fix SPI, priority, redaction, allowlist guard, diff (no Spring) |
| `securetest-reporting` | Dependency-free PDF, XLSX and CSV writers |
| `securetest-adapters` | Built-in scanners + SonarQube, Trivy, OSV, ZAP, JMeter, Playwright, Checkov and Prowler adapters; rule-based fixes |
| `securetest-migration-engine` | Compatibility matrix, assessment, plan, transforms, change sets with backup/commit/undo |
| `securetest-ai` | Opt-in AI-assisted remediation on the official Anthropic Java SDK (structured output, redaction, validation, budget, provenance) |
| `securetest-dashboard-ui` | Offline single-page dashboard (no CDN, no build step), served like a webjar |
| `securetest-spring-boot-autoconfigure` | Auto-configuration, REST API, RBAC/auth filter, orchestration, persistence, telemetry |
| `securetest-spring-boot-starter` | The one dependency to add |
| `securetest-control-plane` | Enterprise control plane: PostgreSQL/Flyway schema, agent registration, OIDC + tenant RBAC, inventory, findings aggregation, remote job queue, reports, audit |
| `securetest-worker` | Remote worker: pulls jobs, runs the adapters' scanners in a sandbox container, posts normalized findings |
| `securetest-sample-app` | Demo app + end-to-end acceptance tests (embedded, and registration + remote scan through the control plane) |

## Deploying the control plane

The **Enterprise Control Plane** and **Embedded + Remote Worker** profiles add two deployables to the embedded starter:

```
 app + starter --register/heartbeat--> control plane <--claim/heartbeat/results-- worker --> sandbox container --> target
 (enrollment token)                    (PostgreSQL, OIDC)                   (fleet token)      (one per job)
```

* **Control plane** (`securetest-control-plane`, Spring Boot, port 8090). It keeps a tenant / organization / project / application /
  environment inventory and agent registrations. It also aggregates and de-duplicates findings from all applications, queues remote
  scans, renders reports with `securetest-reporting`, and writes a hash-chained audit trail. The schema is created by Flyway on start-up.
* **Worker** (`securetest-worker`). It pulls jobs for the scanners it serves, runs each job in a throw-away container, sends lease
  heartbeats, and posts normalized findings back. It serves the `securetest-adapters` scanners that need a network target and no source
  workspace: passive HTTP checks, active probes, API contract, TLS, ports, load test, ZAP, JMeter and Prowler. Source-based scans
  (SAST, secrets, SCA, IaC, tests) stay in the embedded agent, which has the workspace.

### 1. Build the images

```bash
mvn install
docker build -t securetest/control-plane:1.0.0 securetest-control-plane
docker build -t securetest/worker:1.0.0 securetest-worker
```

The runnable jars are `securetest-control-plane/target/securetest-control-plane-1.0.0-exec.jar` and
`securetest-worker/target/securetest-worker-1.0.0-exec.jar`. The plain jars are libraries.

### 2. Run PostgreSQL and the control plane

`securetest-control-plane/deploy/docker-compose.yml` starts PostgreSQL 16 and the control plane. Copy `deploy/.env.example`
to `deploy/.env`, fill it in, then run `docker compose up -d` in `deploy/`. The same settings as environment variables or `application.yml`:

| Setting | Purpose |
|---|---|
| `spring.datasource.url` / `username` / `password` | PostgreSQL 14+ (`jdbc:postgresql://host:5432/securetest`). Flyway creates or migrates the schema (`securetest_schema_history`). |
| `spring.security.oauth2.resourceserver.jwt.issuer-uri` | Your OIDC provider (Keycloak, Entra ID, Okta, Auth0...). Users call the API with its access tokens. `jwk-set-uri` or `public-key-location` also work. |
| `securetest.control-plane.security.tenant-claim` | Token claim that holds the user's tenant slug (default `tenant`). |
| `securetest.control-plane.security.roles-claim` | Token claim that holds roles (default `roles`): `VIEWER`, `DEVELOPER`, `QA`, `DEVOPS`, `SECURITY`, `OWNER`, `ADMIN`; `PLATFORM_ADMIN` manages tenants. |
| `securetest.control-plane.workers.tokens` | Shared secret(s) for the worker fleet. Use a list to rotate without downtime. |
| `securetest.control-plane.bootstrap.tenant-slug` / `enrollment-token` | Optional first tenant and agent enrollment token (stored only as a SHA-256 hash). Idempotent. |
| `securetest.control-plane.jobs.lease` | How long a worker may go without a heartbeat before its job is re-queued (default `2m`; `max-attempts` default 3). |

Only `/actuator/health/**` and `/actuator/info` are public. `POST /api/v1/agents/register` accepts tenant enrollment tokens,
`/api/v1/worker/**` accepts fleet tokens, and every other `/api/**` call needs an OIDC access token. Each of those calls is scoped to
the token's tenant, and a resource from another tenant answers `404`. Put the control plane behind TLS (ingress or load balancer).

Tenant administration: a `PLATFORM_ADMIN` creates tenants with `POST /api/v1/admin/tenants {"slug":"acme"}`. A tenant `ADMIN` issues agent
enrollment tokens with `POST /api/v1/enrollment-tokens`. The raw token is shown once; revoke it with `POST /api/v1/enrollment-tokens/{id}/revoke`.

### 3. Connect applications

Each application that already uses the starter only needs connected mode:

```yaml
securetest:
  control-plane:
    enabled: true
    url: https://securetest.example.com
    enrollment-token-ref: env://SECURETEST_ENROLLMENT_TOKEN   # or file://, vault://
```

The agent registers within seconds and then re-registers every `heartbeat` (default 60 s). It shows up in `GET /api/v1/inventory`.

### 4. Run workers

Run workers on hosts with Docker or Podman that can reach the targets. Start them as `java -jar securetest-worker-1.0.0-exec.jar`:

```yaml
securetest:
  worker:
    control-plane-url: https://securetest.example.com
    token: ${SECURETEST_WORKER_TOKEN}
    allowed-targets: [ "*.staging.example.com", "10.20.0.0/16" ]   # enforced inside the sandbox for every request
    concurrency: 2
    sandbox:
      mode: container            # "process" = child JVM, for development/CI only
      image: securetest/worker:1.0.0
      network: securetest-scan   # a network that reaches the targets and nothing else
      memory: 1g
      cpus: "1.0"
      timeout: 30m
```

Every job runs in a new container started from the worker image with `--read-only`, `--cap-drop ALL`, `no-new-privileges`, a
non-root user, and memory/CPU/PID limits. Only a per-job directory holding `request.json` and `result.json` is mounted. The
sandbox never receives the worker token, the control-plane URL or environment variables. Remote jobs never carry secrets:
options whose names look like credentials are refused when the job is queued.

### 5. Run a remote scan

```bash
curl -X POST https://securetest.example.com/api/v1/scans -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"serviceId":"orders@staging","scannerId":"builtin-http-security","targetUrl":"https://orders.staging.example.com"}'
```

Passive scanners need `EXECUTE`. Active and resource-intensive scanners need `APPROVE` plus `"confirmed": true`. A scanner that no
live worker advertises counts as active. Track the job with `GET /api/v1/scans/{id}`. Results are available at `GET /api/v1/findings`,
`GET /api/v1/findings/summary`, `POST /api/v1/reports {"format":"PDF|XLSX|CSV"}`, `GET /api/v1/audit` and `GET /api/v1/audit/verify`.

Each finding is identified by its tenant, application, environment and fingerprint. A finding that comes back counts as another
occurrence. A fixed finding that comes back is re-opened as a regression. Open findings that the next complete scan by the same scanner
no longer reports are closed automatically. Triage decisions (suppressed, accepted risk, false positive) are kept.

`RemoteScanEndToEndTest` in the sample app runs this whole flow in one JVM. It uses H2 in PostgreSQL mode and the `process` sandbox. With
Docker available, `PostgresSchemaTest` also runs the schema against a real PostgreSQL via Testcontainers.

## Scope of this release

This release implements the **Embedded Local**, **Enterprise Control Plane** and **Embedded + Remote Worker** profiles of the SRS. It deviates in these ways:

* **Control plane scope.** It has no web UI yet (REST API only) and no object storage: reports are stored in PostgreSQL and scanner artifacts from remote jobs are not uploaded. Workers are a platform-operated fleet shared by all tenants, with one fleet token. Remote jobs carry no secrets, so authenticated remote scans are not supported yet. The audit hash chain is serialized per control-plane instance; with several replicas, check it with `/api/v1/audit/verify`.
* **Embedded mode** still runs heavy tools as allowlisted local processes. Use a remote worker to run them in containers.
* **Persistence** is local JSON files plus an append-only, hash-chained audit log in `storage-dir`. A database isn't needed for the embedded profile.
* **Dashboard technology**: dependency-free vanilla JS instead of React, so the jar works offline and air-gapped without a Node build.
* **Device testing** runs your own Appium/Selenium suites through the test runner and imports their JUnit results per device label. SecureTest does not manage device farms.
* **Vulnerability data**: online OSV lookups are opt-in. Spring and Micrometer jars carry no Maven metadata, so their coordinates are inferred from the file name.

Automated findings are advisory and may contain false positives or negatives. Compliance mappings are technical evidence, not certification.

## Contributing and releases

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and [RELEASING.md](RELEASING.md) (Maven Central publishing through GitHub Actions). Licensed under [Apache-2.0](LICENSE).
