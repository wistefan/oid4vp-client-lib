package io.github.wistefan.oid4vp;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.wistefan.oid4vp.config.RequestParameters;
import io.github.wistefan.oid4vp.exception.BadGatewayException;
import io.github.wistefan.oid4vp.exception.Oid4VPException;
import io.github.wistefan.oid4vp.model.OpenIdConfiguration;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.util.Strings;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import static io.github.wistefan.oid4vp.HttpConstants.STATUS_CODE_OK;
import static io.github.wistefan.oid4vp.OID4VPClient.asJson;
import static io.github.wistefan.oid4vp.OIDConstants.*;

@RequiredArgsConstructor
public class OpenIdConfigurationClient {

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    /**
     * Retrieve OpenID-Configuration from the configured endpoint
     */
    public CompletableFuture<OpenIdConfiguration> getOpenIdConfiguration(RequestParameters requestParameters) {
        if (requestParameters.host() == null) {
            throw new Oid4VPException("Request parameters did not contain a host");
        }
        URI wellKnownAddress = normalizeHost(requestParameters.host())
                .resolve(buildPath(requestParameters.path()));
        HttpRequest wellKnownRequest = HttpRequest.newBuilder(wellKnownAddress).GET().build();

        return httpClient.sendAsync(wellKnownRequest, asJson(objectMapper, OpenIdConfiguration.class))
                .thenApply(response -> {
                    if (response.statusCode() == STATUS_CODE_OK) {
                        return response.body(); // success path
                    }
                    throw new BadGatewayException(
                            String.format("Was not able to retrieve OpenId Configuration from %s - status: %s",
                                    wellKnownAddress,
                                    response.statusCode()
                            ));
                })
                .thenApply(openIdConfiguration -> {
                    validateOpenIDConfiguration(openIdConfiguration, requestParameters);
                    return openIdConfiguration;
                });
    }

    /**
     * Normalize the host URI to scheme + host + port only, stripping any
     * path, query, or fragment.  Also handles the case where the URI
     * contains a literal {@code :-1} port (produced when code serializes
     * {@link URI#getPort()} for a URI without an explicit port): such a
     * port makes the authority server-based unparseable, so
     * {@link URI#getHost()} returns {@code null}.  We fall back to
     * parsing the authority string directly in that case.
     */
    private static URI normalizeHost(URI host) {
        String hostname = host.getHost();
        int port = host.getPort();

        if (hostname == null) {
            // Authority may contain a literal ":-1" or other non-standard port
            // that prevents Java from parsing the host component.
            String authority = host.getAuthority();
            if (authority != null && authority.contains(":-1")) {
                hostname = authority.substring(0, authority.indexOf(":-1"));
                port = -1;
            } else if (authority != null && authority.contains(":")) {
                hostname = authority.substring(0, authority.lastIndexOf(':'));
                try {
                    port = Integer.parseInt(authority.substring(authority.lastIndexOf(':') + 1));
                } catch (NumberFormatException e) {
                    throw new Oid4VPException("Cannot parse port from host URI: " + host);
                }
            } else {
                throw new Oid4VPException("Cannot determine hostname from URI: " + host);
            }
        }

        try {
            return new URI(host.getScheme(), null, hostname, port, null, null, null);
        } catch (URISyntaxException e) {
            throw new Oid4VPException("Invalid host URI: " + host, e);
        }
    }

    private static String buildPath(String path) {
        path = path.startsWith("/") ? path.substring(1) : path;
        path = path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
        if (path.isEmpty()) {
            return OID_WELL_KNOWN;
        }
        return "/" + path + OID_WELL_KNOWN;
    }

    /**
     * Validate that the provided OpenId-Endpoint supports OpenId4VP
     */
    private void validateOpenIDConfiguration(OpenIdConfiguration openIdConfiguration, RequestParameters requestParameters) {
        if (openIdConfiguration.getAuthorizationEndpoint() == null) {
            throw new BadGatewayException(String.format("The OpenID configuration does not contain an authorization_endpoint: %s", openIdConfiguration));
        }
        if (openIdConfiguration.getTokenEndpoint() == null) {
            throw new BadGatewayException(String.format("The OpenID configuration does not contain an token_endpoint: %s", openIdConfiguration));
        }
        if (openIdConfiguration.getScopesSupported() == null || (requestParameters.scope() != null && !openIdConfiguration.getScopesSupported().containsAll(requestParameters.scope()))) {
            throw new BadGatewayException(String.format("The OpenID configuration does not support all required(%s) scopes: %s", requestParameters.scope(), openIdConfiguration));
        }
        if (openIdConfiguration.getGrantTypesSupported() == null || !openIdConfiguration.getGrantTypesSupported().contains(VP_TOKEN_GRANT_TYPE)) {
            throw new BadGatewayException(String.format("The OpenID configuration does not support vp_token: %s", openIdConfiguration));
        }
        if (openIdConfiguration.getResponseTypesSupported() == null || !openIdConfiguration.getResponseTypesSupported().contains(RESPONSE_TYPE_CODE)) {
            throw new BadGatewayException(String.format("The OpenID configuration does not support the response_type code: %s", openIdConfiguration));
        }
    }

}
