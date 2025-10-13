package io.github.wistefan.oid4vp.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.SignedJWT;
import io.github.wistefan.oid4vp.exception.BadGatewayException;
import io.github.wistefan.oid4vp.exception.ClientResolutionException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.security.PublicKey;
import java.text.ParseException;

import static com.nimbusds.jose.jwk.KeyType.EC;
import static io.github.wistefan.oid4vp.OID4VPClient.asJson;

/**
 * Implementation to support did:web{@see https://w3c-ccg.github.io/did-method-web/} resolution.
 */
@Slf4j
@RequiredArgsConstructor
public class DidWebClientResolver implements ClientResolver {

    private static final String DID_WEB_PREFIX = "did:web:";
    private static final String WELL_KNOWN_PATH = "/.well-known/did.json";

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    @Override
    public boolean isSupportedId(String clientId) {
        return clientId != null && clientId.startsWith(DID_WEB_PREFIX);
    }

    @Override
    public Mono<PublicKey> getPublicKey(String clientId, SignedJWT jwt) {
        if (!isSupportedId(clientId)) {
            throw new ClientResolutionException(String.format("The client %s is not a supported type.", clientId));
        }
        String identifierPart = clientId.replaceFirst(DID_WEB_PREFIX, "");
        boolean containsPath = identifierPart.contains(":");
        if (containsPath) {
            identifierPart = identifierPart.replaceAll(":", "/");
        } else {
            identifierPart = identifierPart + WELL_KNOWN_PATH;
        }
        HttpRequest wellKnownRequest = HttpRequest.newBuilder(URI.create("https://" + identifierPart)).GET().build();
        return Mono.fromFuture(httpClient.sendAsync(wellKnownRequest, asJson(objectMapper, DidDocument.class)))
                .flatMap(response -> {
                    if (response.statusCode() == 200) {
                        return Mono.just(response.body()); // success path
                    } else {
                        return Mono.error(new BadGatewayException(
                                String.format("Was not able to retrieve did document for %s - status: %s",
                                        clientId,
                                        response.statusCode()
                                )));
                    }
                })
                .map(document -> getKeyFromDidDocument("#074cfbf193f046bcba5841ac4751e91bvcSigningKey-46682", document));
    }

    private PublicKey getKeyFromDidDocument(String keyId, DidDocument didDocument) {
        VerificationMethod verificationMethod = didDocument.getVerificationMethod()
                .stream()
                .filter(vm -> vm.getId().equals(keyId))
                .findAny()
                .orElseThrow(() -> new ClientResolutionException(String.format("The keyId %s is not defined in the did-document.", keyId)));
        if (verificationMethod.getPublicKeyJwk() == null) {
            throw new ClientResolutionException("The verification method does not contain a publicKeyJwt.");
        }
        try {
            JWK jwk = JWK.parse(verificationMethod.getPublicKeyJwk());
            return switch (jwk.getKeyType().getValue()) {
                case "RSA" -> ((RSAKey) jwk).toPublicKey();
                case "EC" -> ((ECKey) jwk).toPublicKey();
                case "OKP" -> ((OctetKeyPair) jwk).toPublicKey();
                default -> throw new IllegalArgumentException("Unsupported key type: " + jwk.getKeyType());
            };
        } catch (ParseException e) {
            throw new ClientResolutionException("Was not able to parse the publicKeyJwt.", e);
        } catch (JOSEException e) {
            throw new ClientResolutionException("Was not able to correctly parse the key.", e);
        }


    }

}
