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

import de.grobmeier.sbom.verifier.BillOfMaterials;
import de.grobmeier.sbom.verifier.Component;
import de.grobmeier.sbom.verifier.Component.ExternalReference;
import de.grobmeier.sbom.verifier.EnforcerRule;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import javax.inject.Inject;
import javax.inject.Named;
import org.apache.maven.plugin.MojoFailureException;
import org.codehaus.plexus.logging.Logger;
import org.jspecify.annotations.Nullable;

@Named("validateReferences")
public class ValidateReferencesRule implements EnforcerRule {

    private static final Set<Integer> RESPONSE_CODES_AUTH =
            Set.of(HttpURLConnection.HTTP_UNAUTHORIZED, HttpURLConnection.HTTP_FORBIDDEN);

    private static final Set<Integer> RESPONSE_CODES_REDIRECT =
            Set.of(HttpURLConnection.HTTP_MOVED_PERM, HttpURLConnection.HTTP_MOVED_TEMP);

    private static final int DEFAULT_MAX_FAILURES_PER_HOST = 3;

    private final Logger logger;
    private final HttpUrlChecker urlChecker;
    private final Map<String, Integer> failureCountByHost = new HashMap<>();
    private final Map<String, Integer> skippedByHost = new HashMap<>();
    private final Map<URI, Integer> responseCodeCache = new HashMap<>();

    record ReferenceFinding(String message, boolean unavailable) {}

    /**
     * If {@code true}, the rule will fail if any reference returns a `401` or `403` code.
     */
    private boolean failOnAuth = false;

    /**
     * If {@code true}, the rule will fail if any reference returns a `301` or `302` code.
     */
    private boolean failOnRedirect = false;

    /**
     * If {@code true}, the rule will also check the external references from dependency components.
     */
    private boolean checkDependencies = true;

    /**
     * If {@code true}, the build will also fail if a broken link is encountered in a dependency component.
     * <p>
     *     Otherwise, the problem is logged.
     * </p>
     */
    private boolean failOnDependencies = false;

    /**
     * If true, HTTP 429, HTTP 5xx, and connection failures can fail the build.
     * Dependency findings still follow failOnDependencies.
     */
    private boolean failOnUnavailable = false;

    /**
     * Maximum number of IO errors for each HTTP domain.
     * <p>
     *     After the limit has been reached, the rule will ignore links to that HTTP domain.
     * </p>
     */
    int maxFailuresPerHost = DEFAULT_MAX_FAILURES_PER_HOST;

    /**
     * Set of external reference types to include in the check.
     * <p>
     *     If <em>empty</em>, all types will be checked.
     * </p>
     */
    Set<String> includes = Set.of();

    /**
     * Set of external reference types to exclude from the check.
     * <p>
     *     The default is equivalent to:
     * </p>
     * <pre>
     *     &lt;excludes>
     *         &lt;exclude>distribution-intake&lt;/exclude>
     *     &lt;/excludes>
     * </pre>
     * <p>
     *     The {@code distribution-intake} external reference is usually protected by authentication and is not useful
     *     for the consumers of an artifact.
     * </p>
     */
    Set<String> excludes = Set.of("distribution-intake");

    @Inject
    public ValidateReferencesRule(Logger logger) {
        this(logger, new JreHttpUrlChecker(logger));
    }

    ValidateReferencesRule(Logger logger, HttpUrlChecker urlChecker) {
        this.logger = logger;
        this.urlChecker = urlChecker;
    }

    @Override
    public void execute(BillOfMaterials bom) throws MojoFailureException {
        skippedByHost.clear();
        List<String> errors = new ArrayList<>();
        reportFindings(validateReferences(bom.getComponent()), true, errors);
        if (checkDependencies) {
            for (Component dependency : bom.getDependencies()) {
                reportFindings(validateReferences(dependency), failOnDependencies, errors);
            }
        }
        skippedByHost.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> logger.warn("Skipped " + entry.getValue() + " external reference(s) for host "
                        + entry.getKey() + " after " + maxFailuresPerHost + " connection failures"));

        if (!errors.isEmpty()) {
            String message = errors.stream()
                    .sorted()
                    .collect(Collectors.joining(
                            "\n* ", "SBOM " + bom.getBillOfMaterials() + " contains invalid references:\n\n* ", ""));
            throw new MojoFailureException(message);
        }
    }

    private void reportFindings(List<ReferenceFinding> findings, boolean canFail, List<String> errors) {
        for (ReferenceFinding finding : findings) {
            if (canFail && (!finding.unavailable() || failOnUnavailable)) {
                errors.add(finding.message());
            } else {
                logger.warn(finding.message());
            }
        }
    }

    private List<ReferenceFinding> validateReferences(Component component) {
        return component.getExternalReferences().stream()
                .filter(this::shouldCheck)
                .<ReferenceFinding>mapMulti((ref, consumer) -> {
                    ReferenceFinding finding = validateReference(ref.getLocation());
                    if (finding != null) {
                        consumer.accept(finding);
                    }
                })
                .toList();
    }

    private boolean shouldCheck(ExternalReference externalReference) {
        String referenceType = externalReference.getReferenceType();
        return (includes.isEmpty() || includes.contains(referenceType)) && !excludes.contains(referenceType);
    }

    @Nullable
    ReferenceFinding validateReference(String location) {
        try {
            URI uri = new URI(location);
            String scheme = uri.getScheme();
            if ("http".equals(scheme) || "https".equals(scheme)) {
                URL url = uri.toURL();
                // 1. Skip if error limit exceeded
                Integer failureCount = failureCountByHost.get(url.getAuthority());
                if (failureCount != null && failureCount >= maxFailuresPerHost) {
                    skippedByHost.merge(url.getAuthority(), 1, Integer::sum);
                    return null;
                }
                // 2. Check the URL
                try {
                    Integer responseCode = responseCodeCache.get(uri);
                    if (responseCode == null) {
                        responseCode = urlChecker.getResponseCode(url);
                        responseCodeCache.put(uri, responseCode);
                    } else {
                        logger.debug("Using cached response for URL: " + url);
                    }
                    if (responseCode == HttpURLConnection.HTTP_OK
                            || (!failOnAuth && RESPONSE_CODES_AUTH.contains(responseCode))
                            || (!failOnRedirect && RESPONSE_CODES_REDIRECT.contains(responseCode))) {
                        return null;
                    }
                    if (responseCode == 429 || (responseCode >= 500 && responseCode <= 599)) {
                        return new ReferenceFinding("Unavailable external reference (" + responseCode + "): "
                                + location, true);
                    }
                    return new ReferenceFinding("Broken external reference (" + responseCode + "): " + location, false);
                } catch (IOException e) {
                    failureCountByHost.merge(url.getAuthority(), 1, Integer::sum);
                    return new ReferenceFinding("Unavailable external reference (connection failed): " + location, true);
                }
            }
            return null;
        } catch (URISyntaxException | MalformedURLException e) {
            return new ReferenceFinding("Reference location is not a valid URI: " + location, false);
        }
    }

    public boolean isCheckDependencies() {
        return checkDependencies;
    }

    public void setCheckDependencies(boolean checkDependencies) {
        this.checkDependencies = checkDependencies;
    }

    public boolean isFailOnAuth() {
        return failOnAuth;
    }

    public void setFailOnAuth(boolean failOnAuth) {
        this.failOnAuth = failOnAuth;
    }

    public boolean isFailOnRedirect() {
        return failOnRedirect;
    }

    public void setFailOnRedirect(boolean failOnRedirect) {
        this.failOnRedirect = failOnRedirect;
    }

    public boolean isFailOnDependencies() {
        return failOnDependencies;
    }

    public void setFailOnDependencies(boolean failOnDependencies) {
        this.failOnDependencies = failOnDependencies;
    }

    public boolean isFailOnUnavailable() {
        return failOnUnavailable;
    }

    public void setFailOnUnavailable(boolean failOnUnavailable) {
        this.failOnUnavailable = failOnUnavailable;
    }

    public int getMaxFailuresPerHost() {
        return maxFailuresPerHost;
    }

    public void setMaxFailuresPerHost(int maxFailuresPerHost) {
        this.maxFailuresPerHost = maxFailuresPerHost;
    }

    public int getTimeoutMs() {
        return urlChecker.getTimeoutMs();
    }
    /**
     * Timeout in milliseconds for HTTP/HTTPS requests
     */
    public void setTimeoutMs(int timeoutMs) {
        urlChecker.setTimeoutMs(timeoutMs);
    }

    public Set<String> getIncludes() {
        return Collections.unmodifiableSet(includes);
    }

    public void setIncludes(Set<String> includes) {
        this.includes = includes;
    }

    public Set<String> getExcludes() {
        return Collections.unmodifiableSet(excludes);
    }

    public void setExcludes(Set<String> excludes) {
        this.excludes = excludes;
    }

    interface HttpUrlChecker {

        /**
         * Checks the given URL and returns the response code.
         *
         * @param url A URL
         * @return An HTTP Response code
         * @throws IOException if a connection error occurs.
         */
        int getResponseCode(URL url) throws IOException;

        int getTimeoutMs();

        void setTimeoutMs(int timeoutMs);
    }

    static class JreHttpUrlChecker implements HttpUrlChecker {

        /**
         * HTTP connection and read timeout in milliseconds.
         */
        private int timeoutMs = 5000;

        private final Logger logger;

        JreHttpUrlChecker(Logger logger) {
            this.logger = logger;
        }

        @Override
        public int getTimeoutMs() {
            return timeoutMs;
        }

        @Override
        public void setTimeoutMs(int timeoutMs) {
            this.timeoutMs = timeoutMs;
        }

        @Override
        public int getResponseCode(URL url) throws IOException {
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            try {
                connection.setRequestMethod("HEAD");
                connection.setInstanceFollowRedirects(false);
                connection.setDoInput(true);
                connection.setDoOutput(false);
                connection.setUseCaches(false);
                connection.setConnectTimeout(timeoutMs);
                connection.setReadTimeout(timeoutMs);
                logger.debug("Checking URL: " + url);
                connection.connect();
                return connection.getResponseCode();
            } finally {
                connection.disconnect();
            }
        }
    }
}
