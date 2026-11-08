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

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.github.sbom.enforcer.BillOfMaterials;
import io.github.sbom.enforcer.Component;
import java.util.List;
import java.util.Set;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class CompletenessRuleTest {
    private static MavenProject project(String scope) {
        MavenProject project = new MavenProject();
        project.setGroupId("example");
        project.setArtifactId("app");
        project.setVersion("1");
        project.setArtifacts(Set.of(
                new DefaultArtifact("example", "dep", "2", scope, "jar", null, new DefaultArtifactHandler("jar"))));
        return project;
    }

    private static Component component(String coordinates) {
        Component component = mock(Component.class);
        when(component.getArtifact()).thenReturn(new org.eclipse.aether.artifact.DefaultArtifact(coordinates));
        return component;
    }

    private static BillOfMaterials bom(String root, String dependency) {
        BillOfMaterials bom = mock(BillOfMaterials.class);
        Component rootComponent = component(root);
        when(bom.getComponent()).thenReturn(rootComponent);
        doReturn(dependency == null ? List.of() : List.of(component(dependency)))
                .when(bom)
                .getDependencies();
        return bom;
    }

    @ParameterizedTest
    @ValueSource(strings = {"compile", "runtime"})
    void reportsMissingResolvedDependencies(String scope) {
        CompletenessRule rule = new CompletenessRule();
        rule.setProject(project(scope));
        assertThatThrownBy(() -> rule.execute(bom("example:app:jar:1", null)))
                .hasMessageContaining("Missing dependency: example:dep:jar::2", "scope " + scope);
    }

    @ParameterizedTest
    @ValueSource(strings = {"test", "provided", "system"})
    void excludesNonRuntimeScopes(String scope) {
        CompletenessRule rule = new CompletenessRule();
        rule.setProject(project(scope));
        assertThatCode(() -> rule.execute(bom("example:app:jar:1", null))).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {"example:dep:jar:tests:2", "example:dep:zip:2", "example:dep:jar:3"})
    void distinguishesClassifierTypeAndVersion(String dependency) {
        CompletenessRule rule = new CompletenessRule();
        rule.setProject(project("runtime"));
        assertThatThrownBy(() -> rule.execute(bom("example:app:jar:1", dependency)))
                .hasMessageContaining("Missing dependency");
    }

    @Test
    @SuppressWarnings("deprecation")
    void checksTransitiveResolvedArtifactsBeyondDirectDependencies() {
        MavenProject project = project("compile");
        var direct = project.getArtifacts().iterator().next();
        var transitive = new DefaultArtifact("example", "transitive", "3", "runtime", "jar", null,
                new DefaultArtifactHandler("jar"));
        project.setDependencyArtifacts(Set.of(direct));
        project.setArtifacts(Set.of(direct, transitive));
        CompletenessRule rule = new CompletenessRule();
        rule.setProject(project);
        assertThatThrownBy(() -> rule.execute(bom("example:app:jar:1", "example:dep:jar:2")))
                .hasMessageContaining("Missing dependency: example:transitive:jar::3");
    }

    @Test
    void checksProjectIdentity() {
        CompletenessRule rule = new CompletenessRule();
        rule.setProject(project("runtime"));
        assertThatThrownBy(() -> rule.execute(bom("example:other:jar:1", "example:dep:jar:2")))
                .hasMessageContaining("Project identity mismatch");
    }

    @Test
    void acceptsCompletePomAndExtraComponents() {
        MavenProject project = project("provided");
        project.setPackaging("pom");
        CompletenessRule rule = new CompletenessRule();
        rule.setProject(project);
        assertThatCode(() -> rule.execute(bom("example:app:pom:1", "example:extra:jar:2")))
                .doesNotThrowAnyException();
        rule.setProject(project("runtime"));
        assertThatCode(() -> rule.execute(bom("example:app:jar:1", "example:dep:jar:2")))
                .doesNotThrowAnyException();
    }
}
