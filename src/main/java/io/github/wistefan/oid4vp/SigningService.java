package io.github.wistefan.oid4vp;

import io.github.wistefan.oid4vp.model.VerifiablePresentation;

/**
 * Service to sign verifiable presentations.
 */
public interface SigningService {

    /**
     * Sign the given presentation and return the signed token.
     */
    String signPresentation(VerifiablePresentation verifiablePresentation);
}
