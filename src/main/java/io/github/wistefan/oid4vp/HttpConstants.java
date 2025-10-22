package io.github.wistefan.oid4vp;

/**
 * Constants required for Http-Interaction
 */
public abstract class HttpConstants {

    public static final int STATUS_CODE_OK = 200;
    public static final int STATUS_CODE_REDIRECT = 302;

    public static final String FORM_DELIMITER = "&";
    public static final String SCOPE_DELIMITER = " ";
    public static final String QUERY_DELIMITER = "&";
    public static final String QUERY_PARAM_DELIMITER = "=";
    public static final String QUERY_PART_TEMPLATE = "%s=%s";

    public static final String CONTENT_TYPE_KEY = "Content-Type";
    public static final String CONTENT_TYPE_FORM_ENCODED = "application/x-www-form-urlencoded";
    public static final String HTTP_METHOD_GET = "GET";
}
