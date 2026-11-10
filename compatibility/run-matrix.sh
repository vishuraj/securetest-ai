#!/usr/bin/env bash
# Runs the compatibility app against several Spring Boot versions and both web stacks.
# Usage: compatibility/run-matrix.sh [boot versions...]   (install the starter first: ./mvnw install -DskipTests)
set -uo pipefail
cd "$(dirname "$0")"
MVN=../mvnw
[[ "${OS:-}" == Windows_NT ]] && MVN=../mvnw.cmd
versions=("$@")
[ ${#versions[@]} -eq 0 ] && versions=(3.0.13 3.1.12 3.2.12 3.3.13 3.4.13 3.5.16 4.0.9 4.1.2)
mkdir -p matrix-logs
status=0
for v in "${versions[@]}"; do
  for stack in mvc webflux; do
    log="matrix-logs/boot-$v-$stack.log"
    if "$MVN" -B -ntp -q clean verify -Dboot.version="$v" -P"$stack" > "$log" 2>&1; then
      printf '%-8s %-8s PASS\n' "$v" "$stack"
    else
      printf '%-8s %-8s FAIL  (%s)\n' "$v" "$stack" "$log"
      status=1
    fi
  done
done
exit $status
