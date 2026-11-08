/*
 * Copyright © 2025 Christian Grobmeier, Piotr P. Karwasz
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.sbom.enforcer.rules;

import io.github.sbom.enforcer.BillOfMaterials;
import io.github.sbom.enforcer.EnforcerRule;
import io.github.sbom.enforcer.internal.Artifacts;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import javax.inject.Named;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.artifact.Artifact;

/** Checks whether an SBOM describes the current Maven module and its runtime dependencies. */
@Named("completeness")
public class CompletenessRule implements EnforcerRule {
    private String projectIdentity;
    private Map<String, String> expectedDependencies = Map.of();

    /** Supplies the module whose resolved dependencies define the expected component set. */
    public void setProject(MavenProject project) {
        projectIdentity = project.getGroupId() + ":" + project.getArtifactId() + ":" + project.getVersion();
        expectedDependencies = project.getArtifacts().stream()
                .filter(dependency ->
                        "compile".equals(dependency.getScope()) || "runtime".equals(dependency.getScope()))
                .collect(Collectors.toUnmodifiableMap(
                        dependency -> identity(Artifacts.toArtifact(dependency)),
                        org.apache.maven.artifact.Artifact::getScope,
                        (first, second) -> first));
    }

    @Override
    public void execute(BillOfMaterials bom) throws MojoFailureException {
        if (projectIdentity == null) {
            throw new MojoFailureException("Completeness requires the current Maven project context.");
        }
        var errors = new ArrayList<String>();
        Artifact root = bom.getComponent().getArtifact();
        String expected = projectIdentity;
        String actual = root.getGroupId() + ":" + root.getArtifactId() + ":" + root.getVersion();
        if (!expected.equals(actual)) {
            errors.add("Project identity mismatch: expected " + expected + " but found " + actual);
        }
        Set<String> present = bom.getDependencies().stream()
                .map(component -> identity(component.getArtifact()))
                .collect(Collectors.toSet());
        expectedDependencies.forEach((dependency, scope) -> {
            if (!present.contains(dependency)) {
                errors.add("Missing dependency: " + dependency + " (scope " + scope + ")");
            }
        });
        if (!errors.isEmpty()) {
            throw new MojoFailureException("Incomplete SBOM " + bom.getBillOfMaterials() + ":\n* "
                    + errors.stream().sorted().collect(Collectors.joining("\n* ")));
        }
    }

    private static String identity(Artifact artifact) {
        return artifact.getGroupId() + ":" + artifact.getArtifactId() + ":" + artifact.getExtension() + ":"
                + artifact.getClassifier() + ":" + artifact.getVersion();
    }
}
