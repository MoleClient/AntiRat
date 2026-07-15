# Security policy

## Reporting a vulnerability

Please do not publish working bypasses, credential material, or weaponized malware in a public issue.

Open a private GitHub security advisory for this repository and include:

- the affected AntiRat and Minecraft versions;
- a minimal inert reproduction;
- the expected and observed behavior;
- relevant sanitized logs; and
- whether the report concerns detection, enforcement, quarantine, or tamper resistance.

Never attach real session tokens, Discord tokens, browser data, launcher account stores, private keys, or live webhook credentials.

## Supported releases

Security fixes target the newest AntiRat release. Reports affecting an older Minecraft adapter should identify the exact release JAR and its SHA-256 hash.

## Scope

AntiRat is a defense inside a shared Fabric JVM, not an operating-system sandbox. Reports involving a compromised launcher, modified Fabric Loader, JVM exploit, or hostile operating system are useful context but may require protection outside this project.
