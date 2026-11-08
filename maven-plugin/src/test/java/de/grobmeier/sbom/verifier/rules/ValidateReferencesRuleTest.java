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
package de.grobmeier.sbom.verifier.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sun.net.httpserver.HttpServer;
import de.grobmeier.sbom.verifier.BillOfMaterials;
import de.grobmeier.sbom.verifier.Component;
import de.grobmeier.sbom.verifier.rules.ValidateReferencesRule.HttpUrlChecker;
import de.grobmeier.sbom.verifier.rules.ValidateReferencesRule.JreHttpUrlChecker;
import de.grobmeier.sbom.verifier.support.DefaultBillOfMaterials;
import de.grobmeier.sbom.verifier.support.DefaultComponent;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URL;
import java.nio.channels.ServerSocketChannel;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.apache.maven.plugin.MojoFailureException;
import org.codehaus.plexus.logging.Logger;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

class ValidateReferencesRuleTest {

    private static final URI URI_200 = URI.create("https://example/200");
    // Explicit usage of `http`
    private static final URI URI_301 = URI.create("http://example/301");
    private static final URI URI_302 = URI.create("https://example/302");
    private static final URI URI_401 = URI.create("https://example/401");
    private static final URI URI_403 = URI.create("https://example/403");
    private static final URI URI_404 = URI.create("https://example/404");
    private static final URI URI_408 = URI.create("https://example/408");
    private static final URI URI_429 = URI.create("https://example/429");
    private static final URI URI_500 = URI.create("https://example/500");
    private static final URI URI_503 = URI.create("https://example/503");
    private static final URI URI_EXCEPTION = URI.create("https://example/exception");

    private static final String SSH_URL = "ssh://git@example/repo.git";
    private static final String INVALID_URL = "invalid url";

    @Test
    void urlChecker_works() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        for (int code : new int[] {200, 301, 404}) {
            server.createContext("/" + code, exchange -> {
                exchange.sendResponseHeaders(code, -1);
                exchange.close();
            });
        }
        server.start();
        try {
            JreHttpUrlChecker urlChecker = new JreHttpUrlChecker(mock(Logger.class));
            for (int code : new int[] {200, 301, 404}) {
                URL url = new URL("http://127.0.0.1:" + server.getAddress().getPort() + "/" + code);
                assertThat(urlChecker.getResponseCode(url)).isEqualTo(code);
            }
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Timeout(2)
    void urlChecker_whenNoAnswer_timeoutOccurs() throws IOException {
        try (ServerSocketChannel serverSocketChannel = ServerSocketChannel.open()) {
            serverSocketChannel.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            InetSocketAddress localAddress = (InetSocketAddress) serverSocketChannel.getLocalAddress();
            URL url = new URL("https://" + localAddress.getHostName() + ":" + localAddress.getPort());
            JreHttpUrlChecker urlChecker = new JreHttpUrlChecker(mock(Logger.class));
            urlChecker.setTimeoutMs(500);
            assertThatThrownBy(() -> urlChecker.getResponseCode(url)).isInstanceOf(SocketTimeoutException.class);
        }
    }

    private static HttpUrlChecker createMockHttpUrlChecker() throws IOException {
        HttpUrlChecker urlChecker = mock(HttpUrlChecker.class);
        when(urlChecker.getResponseCode(URI_200.toURL())).thenReturn(200);
        when(urlChecker.getResponseCode(URI_301.toURL())).thenReturn(301);
        when(urlChecker.getResponseCode(URI_302.toURL())).thenReturn(302);
        when(urlChecker.getResponseCode(URI_401.toURL())).thenReturn(401);
        when(urlChecker.getResponseCode(URI_403.toURL())).thenReturn(403);
        when(urlChecker.getResponseCode(URI_404.toURL())).thenReturn(404);
        when(urlChecker.getResponseCode(URI_408.toURL())).thenReturn(408);
        when(urlChecker.getResponseCode(URI_429.toURL())).thenReturn(429);
        when(urlChecker.getResponseCode(URI_500.toURL())).thenReturn(500);
        when(urlChecker.getResponseCode(URI_503.toURL())).thenReturn(503);
        when(urlChecker.getResponseCode(URI_EXCEPTION.toURL())).thenThrow(new IOException("Test exception"));
        return urlChecker;
    }

    static Stream<Arguments> validateReference_successfulConnection() {
        return Stream.of(
                Arguments.of(false, false, URI_200.toASCIIString(), false),
                Arguments.of(false, false, URI_301.toASCIIString(), false),
                Arguments.of(false, false, URI_302.toASCIIString(), false),
                Arguments.of(false, false, URI_401.toASCIIString(), false),
                Arguments.of(true, false, URI_301.toASCIIString(), true),
                Arguments.of(true, false, URI_302.toASCIIString(), true),
                Arguments.of(true, false, URI_401.toASCIIString(), false),
                Arguments.of(false, true, URI_301.toASCIIString(), false),
                Arguments.of(false, true, URI_302.toASCIIString(), false),
                Arguments.of(false, true, URI_401.toASCIIString(), true),
                Arguments.of(false, false, SSH_URL, false));
    }

    @ParameterizedTest
    @MethodSource
    void validateReference_successfulConnection(
            boolean failOnRedirect, boolean failOnAuth, String location, boolean failure) throws IOException {
        HttpUrlChecker urlChecker = createMockHttpUrlChecker();
        Logger logger = mock(Logger.class);
        ValidateReferencesRule rule = new ValidateReferencesRule(logger, urlChecker);
        rule.setFailOnRedirect(failOnRedirect);
        rule.setFailOnAuth(failOnAuth);

        ValidateReferencesRule.ReferenceFinding finding = rule.validateReference(location);
        if (failure) {
            assertThat(finding).as("finding").isNotNull();
            assertThat(finding.message()).contains("Broken external reference");
        } else {
            assertThat(finding).as("finding").isNull();
        }
    }

    static Stream<Arguments> validateReference_failedConnection() {
        return Stream.of(
                Arguments.of(URI_EXCEPTION.toASCIIString(), "Unavailable external reference"),
                Arguments.of(INVALID_URL, "not a valid URI"));
    }

    @ParameterizedTest
    @MethodSource
    void validateReference_failedConnection(String location, String errorMessage) throws IOException {
        HttpUrlChecker urlChecker = createMockHttpUrlChecker();
        Logger logger = mock(Logger.class);
        ValidateReferencesRule rule = new ValidateReferencesRule(logger, urlChecker);

        ValidateReferencesRule.ReferenceFinding finding = rule.validateReference(location);
        assertThat(finding).as("finding").isNotNull();
        assertThat(finding.message()).contains(errorMessage);
    }

    @ParameterizedTest
    @ValueSource(ints = 10)
    @NullSource
    void validateReference_failureCount(@Nullable Integer maxFailuresPerHost) throws IOException {
        HttpUrlChecker urlChecker = createMockHttpUrlChecker();
        Logger logger = mock(Logger.class);
        ValidateReferencesRule rule = new ValidateReferencesRule(logger, urlChecker);
        if (maxFailuresPerHost != null) {
            rule.setMaxFailuresPerHost(maxFailuresPerHost);
        }

        int i;
        for (i = 0; i < rule.maxFailuresPerHost; i++) {
            assertThat(rule.validateReference(URI_EXCEPTION.toASCIIString()).message())
                    .as("finding on attempt %d", i + 1)
                    .contains("Unavailable external reference");
        }
        assertThat(rule.validateReference(URI_EXCEPTION.toASCIIString()))
                .as("error message on attempt %d", i + 1)
                .isNull();
    }

    @Test
    void validateReference_caching() throws Exception {
        HttpUrlChecker urlChecker = createMockHttpUrlChecker();
        Logger logger = mock(Logger.class);
        ValidateReferencesRule rule = new ValidateReferencesRule(logger, urlChecker);

        rule.validateReference(URI_301.toASCIIString());
        verify(urlChecker, times(1)).getResponseCode(URI_301.toURL());
        rule.validateReference(URI_301.toASCIIString());
        verify(urlChecker, times(1)).getResponseCode(URI_301.toURL());
    }

    static Stream<Arguments> failOnDependencies() {
        return Stream.of(
                // Dependencies disabled
                Arguments.of(false, false),
                // Check, but don't fail
                Arguments.of(true, false),
                // Check and fail
                Arguments.of(true, true));
    }

    @ParameterizedTest
    @MethodSource
    void failOnDependencies(boolean checkDependencies, boolean failOnDependencies) throws IOException {
        HttpUrlChecker urlChecker = createMockHttpUrlChecker();
        Logger logger = mock(Logger.class);
        ValidateReferencesRule rule = new ValidateReferencesRule(logger, urlChecker);
        rule.setCheckDependencies(checkDependencies);
        rule.setFailOnDependencies(failOnDependencies);
        // Create BOM
        BillOfMaterials bom = createMockBillOfMaterials(Map.of(), Map.of("website", URI_404.toASCIIString()));

        if (checkDependencies && failOnDependencies) {
            assertThatThrownBy(() -> rule.execute(bom)).isInstanceOf(MojoFailureException.class);
        } else {
            assertDoesNotThrow(() -> rule.execute(bom));
        }
        if (checkDependencies) {
            verify(urlChecker, times(1)).getResponseCode(URI_404.toURL());
        } else {
            verify(urlChecker, never()).getResponseCode(any());
        }
    }

    static Stream<Arguments> failsOnMainComponent() {
        return Stream.of(Arguments.of(URI_404, true), Arguments.of(URI_200, false));
    }

    @ParameterizedTest
    @MethodSource
    void failsOnMainComponent(URI uri, boolean failure) throws IOException {
        HttpUrlChecker urlChecker = createMockHttpUrlChecker();
        Logger logger = mock(Logger.class);
        ValidateReferencesRule rule = new ValidateReferencesRule(logger, urlChecker);
        // Create BOM
        BillOfMaterials bom = createMockBillOfMaterials(Map.of("website", uri.toASCIIString()), Map.of());

        if (failure) {
            assertThatThrownBy(() -> rule.execute(bom))
                    .isInstanceOf(MojoFailureException.class)
                    .hasMessageContaining(uri.toASCIIString());
        } else {
            assertDoesNotThrow(() -> rule.execute(bom));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://example/429", "https://example/500", "https://example/503", "https://example/exception"})
    void unavailableReferencesWarnByDefault(String location) throws IOException {
        HttpUrlChecker urlChecker = createMockHttpUrlChecker();
        Logger logger = mock(Logger.class);
        ValidateReferencesRule rule = new ValidateReferencesRule(logger, urlChecker);
        BillOfMaterials bom = createMockBillOfMaterials(Map.of("website", location), Map.of());

        assertDoesNotThrow(() -> rule.execute(bom));
        verify(logger).warn(org.mockito.ArgumentMatchers.startsWith("Unavailable external reference"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://example/429", "https://example/500", "https://example/503", "https://example/exception"})
    void unavailableReferencesFailInStrictMode(String location) throws IOException {
        HttpUrlChecker urlChecker = createMockHttpUrlChecker();
        ValidateReferencesRule rule = new ValidateReferencesRule(mock(Logger.class), urlChecker);
        rule.setFailOnUnavailable(true);
        BillOfMaterials bom = createMockBillOfMaterials(Map.of("website", location), Map.of());

        assertThatThrownBy(() -> rule.execute(bom))
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("Unavailable external reference")
                .hasMessageContaining(location);
    }

    @Test
    void unavailableDependencyStillFollowsFailOnDependencies() throws IOException {
        HttpUrlChecker urlChecker = createMockHttpUrlChecker();
        ValidateReferencesRule rule = new ValidateReferencesRule(mock(Logger.class), urlChecker);
        rule.setFailOnUnavailable(true);
        BillOfMaterials bom = createMockBillOfMaterials(Map.of(), Map.of("website", URI_503.toASCIIString()));

        assertDoesNotThrow(() -> rule.execute(bom));
        rule.setFailOnDependencies(true);
        assertThatThrownBy(() -> rule.execute(bom))
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("Unavailable external reference (503)");
    }

    @Test
    void status408RemainsBroken() throws IOException {
        ValidateReferencesRule rule = new ValidateReferencesRule(mock(Logger.class), createMockHttpUrlChecker());
        assertThat(rule.validateReference(URI_408.toASCIIString()).unavailable()).isFalse();
    }

    @Test
    void skippedReferencesAreReported() throws IOException {
        HttpUrlChecker urlChecker = mock(HttpUrlChecker.class);
        when(urlChecker.getResponseCode(any(URL.class))).thenThrow(new IOException("Test failure"));
        Logger logger = mock(Logger.class);
        ValidateReferencesRule rule = new ValidateReferencesRule(logger, urlChecker);
        BillOfMaterials bom = createMockBillOfMaterials(
                Map.of("one", "https://example/1", "two", "https://example/2", "three", "https://example/3", "four", "https://example/4"),
                Map.of());

        assertDoesNotThrow(() -> rule.execute(bom));
        verify(logger).warn("Skipped 1 external reference(s) for host example after 3 connection failures");
    }

    static Stream<Arguments> checkIncludeExcludeLogic() {
        return Stream.of(
                Arguments.of(Set.of(), Set.of(), Set.of(URI_200, URI_301, URI_401)),
                Arguments.of(Set.of("foo"), Set.of(), Set.of(URI_200)),
                Arguments.of(Set.of(), Set.of("distribution-intake"), Set.of(URI_200, URI_301)));
    }

    @ParameterizedTest
    @MethodSource
    void checkIncludeExcludeLogic(Set<String> includes, Set<String> excludes, Set<URI> expectedChecks)
            throws Exception {
        HttpUrlChecker urlChecker = createMockHttpUrlChecker();
        Logger logger = mock(Logger.class);
        ValidateReferencesRule rule = new ValidateReferencesRule(logger, urlChecker);
        rule.setIncludes(includes);
        rule.setExcludes(excludes);
        rule.setCheckDependencies(false);
        // Create BOM
        BillOfMaterials bom = createMockBillOfMaterials(
                Map.of(
                        "foo",
                        URI_200.toASCIIString(),
                        "bar",
                        URI_301.toASCIIString(),
                        "distribution-intake",
                        URI_401.toASCIIString()),
                Map.of());

        rule.execute(bom);
        for (URI uri : new URI[] {URI_200, URI_301, URI_401}) {
            if (expectedChecks.contains(uri)) {
                verify(urlChecker, times(1)).getResponseCode(uri.toURL());
            } else {
                verify(urlChecker, never()).getResponseCode(uri.toURL());
            }
        }
    }

    private static BillOfMaterials createMockBillOfMaterials(
            Map<String, String> componentReferences, Map<String, String> dependencyReferences) {
        DefaultBillOfMaterials.Builder builder = DefaultBillOfMaterials.newBuilder()
                .setBillOfMaterials(new DefaultArtifact("groupId:artifactId:xml:cyclonedx:1.0.0"));
        return builder.setComponent(createComponent(componentReferences))
                .addDependency(createComponent(dependencyReferences))
                .get();
    }

    private static Component createComponent(Map<String, String> externalReferences) {
        DefaultComponent.Builder builder =
                DefaultComponent.newBuilder().setArtifact(new DefaultArtifact("groupId:artifactId:1.0.0"));
        externalReferences.forEach(builder::addExternalReference);
        return builder.get();
    }
}
