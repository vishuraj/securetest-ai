# Releasing SecureTest to Maven Central

Published libraries: `securetest-bom`, `securetest-core`, `securetest-reporting`, `securetest-adapters`,
`securetest-migration-engine`, `securetest-ai`, `securetest-dashboard-ui`, `securetest-spring-boot-autoconfigure` and
`securetest-spring-boot-starter`, all under the groupId `io.github.vishuraj`.
The sample app, control plane and worker are applications; they are not published to Central.

## One-time setup

1. **Central Portal account and namespace**
   * Sign in at https://central.sonatype.com with the GitHub account `vishuraj`.
   * The namespace `io.github.vishuraj` is verified automatically for GitHub sign-ins. Otherwise, add it under
     *Namespaces* and follow the verification step (a temporary public repo with the given name).
   * Under *View Account → Generate User Token*, create a token. You get a username and a password.

2. **GPG signing key**
   ```bash
   gpg --full-generate-key                      # RSA 4096, your name + e-mail, strong passphrase
   gpg --list-secret-keys --keyid-format LONG   # note the key id after "rsa4096/"
   gpg --keyserver keyserver.ubuntu.com --send-keys <KEY_ID>
   gpg --armor --export-secret-keys <KEY_ID> > private-key.asc   # for the GitHub secret; delete the file afterwards
   ```

3. **GitHub repository secrets** (*Settings → Secrets and variables → Actions*)

   | Secret | Value |
   |---|---|
   | `CENTRAL_USERNAME` | Central Portal token username |
   | `CENTRAL_PASSWORD` | Central Portal token password |
   | `GPG_PRIVATE_KEY` | content of `private-key.asc` |
   | `GPG_PASSPHRASE` | the key passphrase |

   Optional: create an environment named `maven-central` with required reviewers so every release needs a click.
   Set the repository variable `CENTRAL_AUTO_PUBLISH=true` once you trust the pipeline; until then each upload
   waits in the Central Portal (*Deployments*) for you to press **Publish**.

## Branches and every release

* `develop`: all work happens here. Every push and every pull request runs *Build and test*: the full build on
  Java 17 and 21, and a fresh app using the starter on every Spring Boot line from 3.0 to 4.1 (MVC and WebFlux).
* `master`: release branch. Open a pull request from `develop` to `master` and merge it when the checks pass.

Every merge into `master` runs *Publish to Maven Central*: it builds, tests, signs and uploads the version in the
POMs, then tags that commit `v<version>` and creates the GitHub release. Then open https://central.sonatype.com →
*Deployments*, check the contents and press **Publish** (unless auto-publish is on). If an older upload of the
same version is still waiting there, press **Drop** on it first. Artifacts usually appear on Maven Central within
30 minutes.

Once a version is published, Maven Central never accepts it again, and later merges skip the upload. To release
the next version, raise it on `develop` before merging:

```bash
mvn versions:set -DnewVersion=1.0.1 -DgenerateBackupPoms=false
mvn -f securetest-bom/pom.xml versions:set -DnewVersion=1.0.1 -DgenerateBackupPoms=false
```

Then update the versions inside `securetest-bom/pom.xml` `<dependencyManagement>`, `compatibility/pom.xml`
(`securetest.version`) and `CHANGELOG.md`.

## Compatibility check on your machine

```bash
./mvnw install -DskipTests
compatibility/run-matrix.sh              # every Spring Boot line, MVC and WebFlux
compatibility/run-matrix.sh 4.1.2        # one version
```

## Local dry run (no upload)

```bash
mvn -Prelease -Dgpg.skip -DskipTests verify     # builds sources + javadoc jars like the release
```
