#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"
MOD_VERSION="2.0.0"

(
  cd "$DIST"
  LC_ALL=C LANG=C shasum -a 256 -c SHA256SUMS
)

versions=(1.21.1 1.21.4 1.21.8 1.21.11 26.1 26.1.2 26.2)
for version in "${versions[@]}"; do
  jar="$DIST/antirat-${version}-${MOD_VERSION}.jar"
  [[ -s "$jar" ]]

  if [[ "$version" == 26.* ]]; then
    java_version=25
    class_major=69
  else
    java_version=21
    class_major=65
  fi

  unzip -p "$jar" fabric.mod.json \
    | jq -e --arg minecraft "${version}" --arg java ">=${java_version}" \
      '.version == "2.0.0" and .environment == "client" and
       .depends.fabricloader == ">=0.19.2" and
       .depends.minecraft == $minecraft and .depends.java == $java' >/dev/null

  unzip -p "$jar" antirat.mixins.json \
    | jq -e --arg compatibility "JAVA_${java_version}" \
      '.required == true and .compatibilityLevel == $compatibility' >/dev/null

  manifest="$(unzip -p "$jar" META-INF/MANIFEST.MF)"
  grep -q '^Premain-Class: com.antirat.agent.AntiRatAgent' <<<"$manifest"
  grep -q '^Agent-Class: com.antirat.agent.AntiRatAgent' <<<"$manifest"
  grep -q '^Can-Retransform-Classes: true' <<<"$manifest"

  jar tf "$jar" | grep -q '^assets/antirat/textures/gui/icon.png$'
  javap -verbose -classpath "$jar" com.antirat.AntiRatRuntime \
    | grep -q "major version: ${class_major}"

  echo "Verified AntiRat $version metadata, agent, icon, and Java $java_version bytecode"
done
