package io.github.wistefan.oid4vp.model;

/**
 * Holder for information about the authorization process
 * @param openIdConfiguration - openId configuration from the verifier
 * @param authorizationRequest - the object requesting authorization
 */
public record AuthorizationInformation(OpenIdConfiguration openIdConfiguration,
                                       AuthorizationRequest authorizationRequest) {
}
