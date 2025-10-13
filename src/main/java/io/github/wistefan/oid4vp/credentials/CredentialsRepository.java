package io.github.wistefan.oid4vp.credentials;

import io.github.wistefan.dcql.model.Credential;

import java.util.List;

/**
 * Interface to provide access to the VerifiableCredentials accessible for the authentication process
 */
public interface CredentialsRepository {

    /**
     * Return all credentials
     * @return the list of Credentials
     */
    List<Credential> getCredentials();

}
