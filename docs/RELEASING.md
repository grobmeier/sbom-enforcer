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

# Release SBOM Verifier

Run these commands from the repository root on the release workstation. Use a supported JDK and the Maven wrapper. CI currently uses Java 21.

## Prepare locally

1. Verify that the Central Portal account has access to the verified `de.grobmeier` namespace.
2. Select a valid release signing key that is available on a public keyserver. Use its full primary fingerprint in `RELEASE_SIGNING_KEY`. Unlock the key in the GPG agent.
3. Run the release checks and sign the files locally:

   ```sh
   ./mvnw -B -Prelease -Drevision=0.3.0 -Dgpg.keyname="$RELEASE_SIGNING_KEY" clean verify
   ```

4. Assemble and inspect the local bundle:

   ```sh
   python3 tools/prepare-central-bundle.py --version 0.3.0 --signing-fingerprint "$RELEASE_SIGNING_KEY"
   unzip -l maven-plugin/target/release/central-bundle.zip
   ```

The helper verifies coordinates, plugin prefix, POM metadata, source/Javadoc contents, and all six signatures. It includes the flattened POM, plugin JAR, sources, Javadoc, and CycloneDX XML/JSON attachments with checksums. The flattened POM has no parent dependency, so the build parent is excluded. This is a local preflight, not Central Portal validation.

## Automatic Maven upload and publication

The `central-upload` profile follows the JJSON publication pattern: upload the Maven-built bundle, publish it after Central validation, and wait for the `published` result. No manual ZIP upload or Portal Publish click is required for this path.

Ordinary `release` builds keep upload disabled and automatic publication false. Publication requires both `release` and `central-upload` profiles. Preparing or merging this configuration does not authorize a release invocation.

Use a Central Portal user token in the release workstation environment:

- `CENTRAL_USERNAME`: the Portal token username.
- `CENTRAL_PASSWORD`: the Portal token password.
- `RELEASE_SIGNING_KEY`: the full primary fingerprint of the unlocked, publicly available release signing key.

`docs/maven-release-settings.xml` maps those variables to the dedicated `central-sbom-verifier` server ID. It contains no credentials and does not modify the workstation's private Maven settings. Legacy OSSRH credentials do not establish current Portal access. Do not put actual token values in Git or command-line arguments.

Inspect the release command without invoking Maven or uploading files:

```sh
python3 tools/release-to-central.py --dry-run 0.3.0
```

After the exact source revision passes CI, approve the release notes and create the tag `sbom-verifier-0.3.0` at that revision. After explicit authorization to upload and publish, run:

```sh
python3 tools/release-to-central.py 0.3.0
```

The command requires a clean checkout at the matching tag and the three environment variables. It invokes Maven with `release,central-upload`, the exact release version, explicit signing key, and dedicated settings. Maven performs `clean deploy`, signs the artifacts, uploads, validates, publishes, and waits for publication. Credentials are passed through the environment. The upload path must be exercised only after release authorization; configuration and non-publishing checks do not prove successful Central authentication or publication.

No workflow publishes on push, merge, or tag creation. The release preflight workflow only runs tests and release-profile verification with signing skipped.

## Guava alert disposition

Dependabot alert #1 (CVE-2026-102554 / GHSA-xxph-c9ww-hj94) concerns Guava native Java deserialization. Static review found no native Java object-stream deserialization in the plugin's production sources; the inspected SBOM entrypoint uses CycloneDX XML/JSON parsers. The affected Guava appears through the `provided` Maven core API baseline. The executing Maven distribution controls the actual host version.

The verdict is **needs review**, with medium confidence. No exploitable path in this plugin was confirmed, and host/extension deserialization paths were not fully reviewed. Keep the alert open. Do not claim that the dependency is fixed or dismiss the alert as a false positive. Updating only a provided dependency cannot update the Maven host. Review the Maven distribution used for release and track upstream fixes. This disposition records the current evidence and its limits; it is not an exploit test.

## Release gates

- Review and commit preparation. Run CI on the exact final commit.
- Review the advisory disposition above and select the final release revision.
- Approve the notes and tag that revision. Rebuild from the exact tagged source.
- Obtain explicit authorization before invoking the uploading release command. Central publication is immutable.
- Confirm that Maven reports publication, then resolve the coordinates from a clean repository.
- Update consumer profiles and the website to `0.3.0`, then advance development to the next snapshot.

## References

- [Central artifact requirements](https://central.sonatype.org/publish/requirements/)
- [Central Maven publisher](https://central.sonatype.org/publish/publish-portal-maven/)
- [Central namespace access](https://central.sonatype.org/register/namespace/)
