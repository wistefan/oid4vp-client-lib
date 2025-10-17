package io.github.wistefan.oid4vp;

/**
 * Constants required for interaction with OID
 */
public abstract class OIDConstants {

    public static final String OID_WELL_KNOWN = "/.well-known/openid-configuration";
    public static final String VP_TOKEN_GRANT_TYPE = "vp_token";
    public static final String RESPONSE_TYPE_KEY = "response_type";
    public static final String RESPONSE_MODE_DIRECT_POST = "direct_post";
    public static final String RESPONSE_TYPE_VP_TOKEN = "vp_token";
    public static final String RESPONSE_TYPE_CODE = "code";

    public static final String LOCATION_HEADER = "Location";
    public static final String OPENID_4_VP_SCHEME = "openid4vp";

    public static final String STATE_KEY = "state";
    public static final String NONCE_KEY = "nonce";
    public static final String CLIENT_ID_KEY = "client_id";
    public static final String SCOPE_KEY = "scope";
    public static final String GRANT_TYPE_KEY = "grant_type";
    public static final String REQUEST_KEY = "request";
    public static final String REQUEST_URI_KEY = "request_uri";
    public static final String REQUEST_URI_METHOD_KEY = "request_uri_method";
}
