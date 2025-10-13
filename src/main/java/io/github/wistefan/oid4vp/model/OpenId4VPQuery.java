package io.github.wistefan.oid4vp.model;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

/**
 * Data container holding information from an openid4vp authorization request
 */
@Slf4j
@Data
public class OpenId4VPQuery {

    private static final String CLIENT_ID_KEY = "client_id";
    private static final String REQUEST_KEY = "request";
    private static final String REQUEST_URI_KEY = "request_uri";
    private static final String REQUEST_URI_METHOD_KEY = "request_uri_method";

    private String clientId;
    private URI requestUri;
    private String requestUriMethod;
    private String request;

    /**
     * Parses the query string to its parts and returns the actual query object
     */
    public static OpenId4VPQuery fromQueryString(String queryString) {
        OpenId4VPQuery openId4VPQuery = new OpenId4VPQuery();

        List<String> queryParts = Arrays.asList(queryString.split("&"));
        queryParts.forEach(
                queryPart -> {
                    String[] queryParam = queryPart.split("=");
                    if (queryParam.length != 2) {
                        throw new IllegalArgumentException(String.format("Query contains invalid parameters. Parameter was: %s", queryPart));
                    }
                    switch (queryParam[0]) {
                        case CLIENT_ID_KEY -> openId4VPQuery.setClientId(queryParam[1]);
                        case REQUEST_KEY -> openId4VPQuery.setRequest(queryParam[1]);
                        case REQUEST_URI_KEY -> openId4VPQuery.setRequestUri(URI.create(queryParam[1]));
                        case REQUEST_URI_METHOD_KEY -> openId4VPQuery.setRequestUriMethod(queryParam[1]);
                        default -> log.info("Param {} is unknown, we ignore it.", queryParam[0]);
                    }
                });
        return openId4VPQuery;
    }
}
