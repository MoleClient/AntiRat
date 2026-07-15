#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"
MOD_VERSION="2.0.0"
LEGACY_GRADLE_HOME="${ANTIRAT_LEGACY_GRADLE_HOME:-${TMPDIR:-/tmp}/antirat-gradle-legacy}"
MODERN_GRADLE_HOME="${ANTIRAT_MODERN_GRADLE_HOME:-${TMPDIR:-/tmp}/antirat-gradle-modern}"

find_java_home() {
  local version="$1"
  local override_name="JAVA${version}_HOME"
  local override="${!override_name:-}"
  if [[ -n "$override" ]]; then
    printf '%s\n' "$override"
    return
  fi
  if [[ -x /usr/libexec/java_home ]]; then
    /usr/libexec/java_home -v "$version"
    return
  fi
  printf 'Set %s to a JDK %s installation.\n' "$override_name" "$version" >&2
  exit 1
}

JAVA21_HOME="$(find_java_home 21)"
JAVA25_HOME="$(find_java_home 25)"
mkdir -p "$DIST"

legacy_versions=(1.21.11 1.21.8 1.21.4 1.21.1)
for version in "${legacy_versions[@]}"; do
  echo "Building AntiRat for Minecraft $version with Java 21"
  JAVA_HOME="$JAVA21_HOME" GRADLE_USER_HOME="$LEGACY_GRADLE_HOME" \
    "$ROOT/gradlew" --no-daemon -p "$ROOT" \
    clean test build -Ptarget_mc="$version"
  cp "$ROOT/build/libs/antirat-${version}-${MOD_VERSION}.jar" \
    "$DIST/antirat-${version}-${MOD_VERSION}.jar"
done

modern_versions=(26.1 26.1.2 26.2)
for version in "${modern_versions[@]}"; do
  echo "Building AntiRat for Minecraft $version with Java 25"
  JAVA_HOME="$JAVA25_HOME" GRADLE_USER_HOME="$MODERN_GRADLE_HOME" \
    "$ROOT/gradlew" --no-daemon -p "$ROOT/platform/modern" \
    clean test build -Ptarget_mc="$version"
  cp "$ROOT/platform/modern/build/libs/antirat-${version}-${MOD_VERSION}.jar" \
    "$DIST/antirat-${version}-${MOD_VERSION}.jar"
done

(
  cd "$DIST"
  LC_ALL=C LANG=C shasum -a 256 antirat-*-${MOD_VERSION}.jar > SHA256SUMS
)

echo "Built seven release JARs in $DIST"
cat "$DIST/SHA256SUMS"
