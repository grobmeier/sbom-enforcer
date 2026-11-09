<!--
Copyright © 2026 Christian Grobmeier

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Develop SBOM Verifier

Use this guide for workstation setup and local verification. Use [RELEASING.md](RELEASING.md) for signing, credentials, and publication. Keep current task status in the workspace's `TODO_STATE.md` when that file exists. Check the actual branch, consumer POMs, and publication state before continuing earlier work.

## Project identity

| Item | Value |
| --- | --- |
| Project | SBOM Verifier |
| Maven group | `de.grobmeier` |
| Maven plugin artifact | `sbom-verifier-maven-plugin` |
| Java package | `de.grobmeier.sbom.verifier` |
| Goal | `sbom-verifier:check` |
| Source repository | `https://github.com/grobmeier/sbom-enforcer` |

The repository name retains the original project name. The maintained fork uses the new coordinates and Java package. Preserve the original license and contributor notices. Changes go to the personal fork; an upstream contribution requires a separate decision.

## Workstation setup

1. Read the workspace and repository instructions. Check `git status --short --branch` and `git remote -v`. Preserve unrelated changes and check the destination before pushing.
2. Use JDK 21 to match CI. The source targets Java 17, and `.java-version` contains `17`; this does not mean CI runs on Java 17.
3. Use `./mvnw` from the repository root. The wrapper selects Maven 3.9.9. Use Python 3 and Git for the release-command tests. GPG and Portal credentials are needed for signing/publication, not for ordinary development.
4. Run the normal verification:

   ```sh
   ./mvnw -B verify
   PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tools -p 'test_*.py' -v
   ```

5. Install the development snapshot before testing it in another project:

   ```sh
   ./mvnw -B install
   ```

Read the current version from `pom.xml`; do not assume that a previous snapshot or release is installed. `install` writes to the workstation's local Maven repository. It does not publish to Central.

## Source map

| Location | Purpose |
| --- | --- |
| [CheckMojo](../maven-plugin/src/main/java/de/grobmeier/sbom/verifier/CheckMojo.java) | Find supported attached SBOMs, create rules, and run checks |
| [Rules](../maven-plugin/src/main/java/de/grobmeier/sbom/verifier/rules) | Completeness, checksum, and reference checks |
| [CycloneDX support](../maven-plugin/src/main/java/de/grobmeier/sbom/verifier/internal/cyclonedx) | Parse XML/JSON and map components to Maven artifacts |
| [Maven integration builds](../maven-plugin/src/it) | Passing and failing consumer builds, including expected diagnostics |
| [Rule reference](../maven-plugin/src/site/asciidoc/rules.adoc) | User-facing rule configuration |
| [Release tools](../tools) | Local bundle verification and the explicit publication command |

## Consumer checks

Use the consumer project's declared Java and Maven setup. Confirm that its POM contains the `sbom-verifier` profile and the current plugin coordinates/version before running these examples. Some consumer profile edits can exist only in a local checkout; a fresh clone may not contain them.

Confirm that the build log includes `sbom-verifier:VERSION:check`. A successful consumer build without that goal is not evidence that the plugin ran. A locally installed snapshot is not available to a clean CI runner until that runner installs it or the plugin is published.

### JJSON

From the JJSON checkout root:

```sh
mvn -B -Psbom-verifier -Dgpg.skip=true -Dmaven.javadoc.skip=true verify
```

The profile is in the core module's `jjson/pom.xml`. It generates and attaches a CycloneDX SBOM, then runs completeness, checksum, and reference checks. CycloneDX needs `skipNotDeployed=false` here because the module skips deployment. Signing and Javadoc generation are skipped by this consumer command.

### Time & Bill

Use an isolated worktree from the agreed current branch. The workspace task state records the owner's worktree location; preserve other Time & Bill checkouts and local edits.

From that worktree root:

```sh
mvn -B -Pdevelopment,sbom-verifier -DskipTests verify
```

Keep the `development` profile explicit: activating another profile can deactivate a profile that is active by default. This check builds the application and verifies its generated XML/JSON SBOMs. It skips application tests and does not establish application or deployment acceptance.

Inspect Spring Boot's inherited CycloneDX configuration when adding the profile. The validated setup disables the inherited `default` execution and schedules one `make-sbom` execution, so it does not generate the same SBOM twice. The Time & Bill profile enables completeness and requires an SBOM; it does not run reference checks.

## Verification boundaries

- The `check` goal checks supported attachments for each current Maven module. It reads CycloneDX XML and JSON.
- Enable both `requireSbom=true` and `<completeness/>` to require an SBOM and check its project identity and resolved compile/runtime dependency coverage.
- Completeness excludes provided, test, and system dependencies and permits extra SBOM components. It does not inspect the contents of a packaged or shaded archive.
- A checksum check verifies recorded checksums; it does not require missing checksums to be added.
- HTTP 429, HTTP 5xx, and connection failures warn by default. Dependency failures also follow `failOnDependencies`.
- The existing BOM builder downloads dependency SBOMs even when only completeness is enabled. Account for this cost when comparing cold and cached build times.

## Signing and publication setup

Follow [the signing-key procedure](RELEASING.md#unlock-the-signing-key). The owner's configured release key ends in `A5CC90DB`; verify the current full fingerprint and public-key availability before a release. Do not substitute the Git commit signing key automatically. The earlier commit signing key and the published Maven release key were different.

The publication command uses `CENTRAL_USERNAME`, `CENTRAL_PASSWORD`, and `RELEASE_SIGNING_KEY`. Use a Central Portal token, keep its values outside Git and command-line arguments, and map it through [the dedicated Maven settings](maven-release-settings.xml). Browser sign-in does not populate these environment variables. The dedicated server ID avoids ambiguous `central` entries in private Maven settings.

Inspect the command without running Maven or uploading files:

```sh
python3 tools/release-to-central.py --dry-run 0.3.0
```

The actual command requires a clean checkout at `sbom-verifier-VERSION`. It automatically uploads, validates, publishes, and waits for the result. Run it only after explicit release authorization. Pushes, merges, tag creation, and release-preflight CI do not publish.

Build outputs and candidate bundles under `target/` are disposable. Rebuild and sign from the approved tagged revision. A local bundle check does not replace Central validation or a clean dependency-resolution check after publication.

## Common setup problems

| Symptom | Check |
| --- | --- |
| Maven cannot find the development plugin | Install the current plugin snapshot and match its exact coordinates/version in the consumer |
| Consumer succeeds without a plugin check | Verify the profile exists and the `sbom-verifier:VERSION:check` goal appears in the log |
| No SBOM attached | Check generator execution order and `skipNotDeployed`; run generation before `verify` |
| Duplicate CycloneDX generation | Inspect inherited executions and use one explicit generation execution |
| Mimir reports a socket permission error | Check sandbox and daemon permissions; this can occur before Java compilation |
| GPG cannot sign non-interactively | Unlock the correct release key in the agent, then retry the local signing check |
| Central upload cannot authenticate | Check the Portal token variables and dedicated server ID; legacy credentials or browser login do not prove Maven token access |

See [the Guava review](RELEASING.md#guava-alert-disposition) before changing the provided Maven API dependencies. A version override in this plugin does not replace libraries supplied by the executing Maven distribution.
