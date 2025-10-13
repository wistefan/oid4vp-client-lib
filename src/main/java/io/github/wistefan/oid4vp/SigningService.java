package io.github.wistefan.oid4vp;

import io.github.wistefan.oid4vp.model.VerifiablePresentation;

public interface SigningService {

    String signPresentation(VerifiablePresentation verifiablePresentation);
}
