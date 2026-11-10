# Contributing

Thanks for helping improve SecureTest.

## Build

Java 17+ and Maven 3.9+.

```bash
mvn verify                      # build and run every test
mvn -pl securetest-sample-app spring-boot:run   # dashboard at http://localhost:8080/securetest
```

## Pull requests

* Open an issue first for larger changes so the design can be agreed.
* Keep changes focused; add or update tests for behaviour changes.
* New scanners implement `com.securetest.core.spi.Scanner` and must respect the target allowlist,
  confirmation/approval rules and redaction (see the security model in the README).
* Optional features must stay **off by default**.
* Open pull requests against `develop`. CI (`.github/workflows/build.yml`) must pass on Java 17 and 21 and on every
  Spring Boot line in the compatibility matrix (`compatibility/run-matrix.sh` runs it locally).

By contributing you agree that your contributions are licensed under the Apache License 2.0.
