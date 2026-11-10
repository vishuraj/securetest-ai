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
  <version>1.0.1</version>
</dependency>
```

Gradle:

```groovy
implementation "io.github.vishuraj:securetest-spring-boot-starter:1.0.1"
```

That is all: start the app and open `/securetest`. Every optional module starts disabled; you switch modules on and give
targets, credentials and permissions in the dashboard or in `application.yml`. To align several SecureTest modules, import
`io.github.vishuraj:securetest-bom` instead of repeating the version.

Requirements: Java 17+ and **Spring Boot 3.0 – 4.1** (every 3.x and 4.x line), with **Spring MVC or Spring WebFlux**. It works with or without Spring Security, in every profile including production, and from any machine. One jar covers all of them; there is no separate artifact per Boot version.

| | Tested on every build |
|---|---|
| Spring Boot | 3.0, 3.1, 3.2, 3.3, 3.4, 3.5, 4.0, 4.1 (latest patch of each) |
| Web stack | Spring MVC and Spring WebFlux, each with Spring Security |
| Java | 17 and 21 in CI; the whole matrix also passes on Java 25 |
| Jackson | 2 (Boot 3) and 3 (Boot 4) |

Spring Boot 2.x (`javax.*`, Java 8/11) is not supported. On Spring Boot 3.0/3.1 with WebFlux, SecureTest's API runs on Reactor's shared worker threads instead of its own pool, because Spring Framework 6.0 lacks the hook for that.

**Signing in.** On the machine running the app you go straight in. From anywhere else, or under a `prod`/`production` profile, the browser asks you to sign in. Use user `admin` and the password SecureTest printed in the startup log the first time it ran. The password is also stored in `~/.securetest/<app-name>/initial-admin-password`. To use your own sign-in instead, configure users, OIDC or container authentication.

## Build and try it

No Maven installation needed: the Maven Wrapper downloads Maven 3.9.16 on first use (`mvnw.cmd` on Windows, `./mvnw` elsewhere).

```bash
./mvnw install
java -jar securetest-sample-app/target/securetest-sample-app-1.0.1.jar --securetest.workspace.source-root=securetest-sample-app
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
| Pentest / VAPT | Engagements: scope, rules of engagement, testers, dates, methodology checklist (OWASP WSTG categories, API Top 10 2023, MASVS v2, network), findings, retest phase, engagement report and completion letter | — |
| Attack Surface | Register domains/hosts; discover subdomains; check HTTPS, redirects, certificate expiry, version banners and exposed admin/CI tools; daily monitoring; alerts for new hosts, expiring certificates and new high/critical CVEs | crt.sh certificate logs (opt-in) |
| AI / LLM Security | OWASP Top 10 for LLM Applications: LLM SDK inventory, hard-coded model keys, user input in system prompts, model output to exec/SQL/HTML, risky tools, prompts in logs, token limits; active prompt-injection test of your chat endpoint | — |

**Every module is off by default**, Health included. A tester, developer or manager switches on what they need in the dashboard
(or in configuration, e.g. from a config server).

Cross-cutting: findings with a normalized priority and the preserved source severity ("why this priority?"), dedupe by fingerprint, regression
detection, governed exceptions (reason, owner, expiry, approver), code highlighting that detects stale files, rule-based fixes as diff-first
change sets with a rollback point and undo with conflict detection, opt-in AI-assisted fixes (Claude), PDF/XLSX/CSV/JSON reports, scheduled scans,
saved profiles, a hash-chained audit log, webhooks (Slack/Teams/generic) and e-mail, a release gate (`GET /securetest/api/v1/gate`) and an OpenAPI document for its own API.

You can add your own scanner by declaring a `@Bean` that implements `com.securetest.core.spi.Scanner`. Your own fix provider is a `@Bean` that implements `FixProvider`.

## Safe to ship in production

The dependency can stay in your production build. Until someone uses SecureTest:

* every module is off, and nothing runs in the background: no scheduler, no metrics sampler, no request timing, no outbound
  calls, no data written (the data store only writes after a change; housekeeping starts on first use);
* the public parts (`/.well-known/security.txt` and the disclosure form) do not exist unless you turn the disclosure program on;
* the dashboard and its API need sign-in from any other machine and always under a `prod` profile;
* per request of your application, SecureTest only checks whether the path is the dashboard's and whether Runtime Metrics is on.

Measured with the sample app (Spring Boot 3.5, Java 25, Windows; 3 starts each, all modules off) against the same app with
`securetest.enabled=false`: about +1.1 MB heap after a full GC, about 600 more loaded classes, no extra threads, and
roughly 1–2 s more startup (mostly Spring wiring SecureTest's endpoints). `ZeroFootprintTest` and the compatibility app
check the "no background work" part on every build. To remove SecureTest entirely from an environment,
set `securetest.enabled=false`.

## Team workflows

Everything below runs only when someone uses it. It is for your own testers, developers, security staff and managers, not
for your application's end users.

* **Retest and verified fixes.** *Retest* on a finding re-runs the scanner that found it. If the issue is gone, the finding is
  **verified fixed**; if not, it is marked **still present**. Findings reported by people wait for a tester's verdict.
* **Findings from testers.** *Report finding* records a manual finding (pentest, exploratory testing) with steps to reproduce,
  impact, CWE and evidence. Secrets are redacted. Findings have comments and evidence attachments (screenshots, HAR, logs, PDF;
  5 MB each).
* **Jira and GitHub issues.** One click creates an issue from a finding; *Refresh* reads its state. The issue text is redacted
  and never contains raw evidence.
  ```yaml
  securetest:
    integrations:
      jira:   { url: https://acme.atlassian.net, project-key: SEC, email: qa@acme.com }   # token: SECURETEST_JIRA_TOKEN
      github: { repository: acme/shop }                                              # token: SECURETEST_GITHUB_TOKEN
  ```
* **Pentest engagements** (Pentest / VAPT module). Plan, test against the checklist, report findings into the engagement,
  move to *Retest* (every open finding is queued for retest), complete, and export the engagement report or completion letter.
* **Release readiness.** A release gets live checks (release gate, critical vulnerabilities, code quality, tests,
  performance, compliance, linked pentest), a checklist, waivers that need a reason, and sign-off by role (QA, Security and
  Owner by default). Approval freezes the evidence; the readiness report is the record.
* **Security assistant.** With AI on (`securetest.ai.enabled` and `data-processing-approved`), ask what findings mean, what to
  fix first or how to fix one. Findings are redacted before they are sent, and the assistant treats finding text as data.
* **Vulnerability disclosure program** (off by default). Publishes `/.well-known/security.txt` (RFC 9116) and a no-JavaScript
  report form for outside security researchers, with spam and rate protection. Reports arrive in a triage queue; accepting one
  creates a finding. No bounty payments.
  ```yaml
  securetest:
    disclosure:
      enabled: true
      contact: [mailto:security@acme.com]
      policy: https://acme.com/security-policy
  ```
* **Agency / multi-client workspace.** In the *All services* view, give each service a client and, if each client has its own
  secret, that client's token. The page then groups services by client, and the *Portfolio report* covers all of them.
  ```yaml
  securetest:
    fleet:
      members:
        - { name: api, client: Acme,   url: https://api.acme.example,   token-ref: env://ACME_FLEET_TOKEN }
        - { name: api, client: Globex, url: https://api.globex.example, token-ref: env://GLOBEX_FLEET_TOKEN }
  ```

## Monoliths and microservices

SecureTest works out which kind of system it is in, and the dashboard adapts:

| Your system | What you add | What you get |
|---|---|---|
| **Monolith** (one Spring Boot app, any number of Maven/Gradle modules) | The dependency in the app's POM, or in the parent POM | One dashboard at `/securetest` with every module |
| **Microservices** (one repo with a parent POM) | The dependency **once**, in the parent POM's `<dependencies>` | Every service gets its own dashboard **plus** an **All services** page |

**Microservices: one dependency for every service.** In the parent POM:

```xml
<dependencies>
  <dependency>
    <groupId>io.github.vishuraj</groupId>
    <artifactId>securetest-spring-boot-starter</artifactId>
    <version>1.0.1</version>
  </dependency>
</dependencies>
```

Each module then behaves correctly on its own:

* **Business services** get every module: testing, code quality, vulnerabilities, API security, performance, compliance, health.
* **Spring Cloud infrastructure** (Config Server, Eureka server, Spring Cloud Gateway, Spring Boot Admin) is detected and runs
  as *infra*: health, metrics, performance and security checks, without the source-code modules (testing, code quality,
  migration). Override with `securetest.role: service` or `infra`.
* **Shared libraries** (modules that are not web applications) are untouched: nothing starts.

**All services.** The page appears automatically when SecureTest finds a microservice system. The signals are a service
registry client (Eureka, Consul, Zookeeper, Nacos, Kubernetes), a Spring Cloud Config client, a Spring Cloud infrastructure
app, other services found by discovery, or services you list yourself. In a monolith it never appears. Open it from any
service's dashboard. It shows every service and instance with health, requests per second, p95 latency, error rate,
release gate, open critical/high findings and the state of each module. **Open** shows that service's own dashboard
through the one you are on, with the same sign-in, so a single URL covers the whole system.

* **Finding the services:** Spring Cloud service discovery is used when the app has it (Eureka, Consul, Kubernetes...).
  Without it, list them:
  ```yaml
  securetest:
    fleet:
      members:
        - { name: orders, url: http://orders:8081 }
        - { name: users,  url: http://users:8082 }
  ```
* **Trust between services:** give every service the same secret in `SECURETEST_FLEET_TOKEN` (an environment variable,
  `.env`, or your config server). Services on one machine work without it. The token lets one service act for its signed-in
  user on the others, so treat it like an admin password.
* **Shared settings in one place:** with a Spring Cloud Config Server, put SecureTest settings in its shared
  `application.yml` and every service picks them up. For example:
  ```yaml
  securetest:
    modules:
      metrics: { enabled: true }        # request rate and latency on the All services page
    dashboard:
      authentication:
        provider: basic                 # or oidc
        users:
          - { username: admin, password: "{env}SECURETEST_ADMIN_PW", roles: [ADMIN] }
  ```
* **Drill-down paths:** a service's dashboard is reached at `/securetest/fleet/<service>/`. A service whose dashboard
  lives at a different path can publish it in its registry metadata as `securetest-path`.

## Security model (secure by default)

* **Dashboard**: on in every environment; set `securetest.dashboard.enabled=false` to switch it off. It is never open without sign-in beyond the local machine, and in production sign-in is always required.
* **Local vs remote**: a request counts as local only when it comes from a loopback address *and* carries no proxy forwarding headers, so a reverse proxy on the same host never turns remote users into local administrators. `bind-address: 127.0.0.1` switches to strict local-only mode (remote clients get 403).
* **Authentication** (`securetest.dashboard.authentication.provider`):
  * `auto` (default): local, non-production requests are a local admin; everyone else signs in with HTTP Basic, using configured users or the generated `admin` user. The password is printed in the log only when it is first generated.
  * `local-dev`: loopback clients act as a local admin; remote clients are rejected.
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

### Spring Security and WebFlux

No configuration is needed:

* **Spring MVC + Spring Security**: SecureTest registers a `WebSecurityCustomizer` that lets Spring Security skip `/securetest/**`, and SecureTest's own gate secures it. Your application's security rules, including Spring Boot's default login, are unchanged.
* **WebFlux (with or without Spring Security)**: a WebFilter runs ahead of Spring Security for `/securetest/**`, authenticates the request and hands it to the dispatcher. API work runs on SecureTest's own threads, never on the event loop.
* **`provider: container`**: SecureTest uses your Spring Security login instead. It is then authenticated by your own security chain, with roles from `SECURETEST_<ROLE>` authorities or `role-mapping`.

## Configuration reference (all optional)

```yaml
securetest:
  enabled: true
  mode: embedded                    # embedded | connected
  dashboard:
    enabled: true                   # default; false switches the dashboard off
    path: /securetest
    bind-address: auto              # auto (default) | 127.0.0.1 = strict local-only
    authentication:
      provider: auto                # auto (default) | local-dev | basic | container | oidc
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
  role: auto                        # auto | service | infra (infra = no testing/code-quality/migration)
  fleet:
    enabled: auto                   # auto: All services page only in a microservice system | true | false
    token-ref: env://SECURETEST_FLEET_TOKEN   # same secret on every service
    discovery: true                 # use Spring Cloud service discovery when present
    members: []                     # [{name, url}] when there is no service discovery
    timeout: 3s
    cache-ttl: 10s
    client: null                    # this app's client name (agency workspaces)
  integrations:                     # Jira / GitHub issues, used only on request
    jira: { url: null, project-key: null, email: null, token-ref: env://SECURETEST_JIRA_TOKEN, issue-type: Bug, api-version: 3 }
    github: { repository: null, api-url: https://api.github.com, token-ref: env://SECURETEST_GITHUB_TOKEN }
  disclosure:                       # vulnerability disclosure program (public), off by default
    enabled: false
    contact: []
    form: true
    expires-after: 180d
    reports-per-hour: 5
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
docker build -t securetest/control-plane:1.0.1 securetest-control-plane
docker build -t securetest/worker:1.0.1 securetest-worker
```

The runnable jars are `securetest-control-plane/target/securetest-control-plane-1.0.1-exec.jar` and
`securetest-worker/target/securetest-worker-1.0.1-exec.jar`. The plain jars are libraries.

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

Run workers on hosts with Docker or Podman that can reach the targets. Start them as `java -jar securetest-worker-1.0.1-exec.jar`:

```yaml
securetest:
  worker:
    control-plane-url: https://securetest.example.com
    token: ${SECURETEST_WORKER_TOKEN}
    allowed-targets: [ "*.staging.example.com", "10.20.0.0/16" ]   # enforced inside the sandbox for every request
    concurrency: 2
    sandbox:
      mode: container            # "process" = child JVM, for development/CI only
      image: securetest/worker:1.0.1
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
