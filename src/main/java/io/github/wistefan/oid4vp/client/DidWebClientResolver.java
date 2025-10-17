package io.github.wistefan.oid4vp.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.SignedJWT;
import io.github.wistefan.oid4vp.exception.BadGatewayException;
import io.github.wistefan.oid4vp.exception.ClientResolutionException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.concurrent.CompletableFuture;

import static io.github.wistefan.oid4vp.OID4VPClient.asJson;

/**
 * Implementation to support did:web{@see https://w3c-ccg.github.io/did-method-web/} resolution.
 */
@Slf4j
@RequiredArgsConstructor
public class DidWebClientResolver implements ClientResolver {

    private static final String DID_WEB_PREFIX = "did:web:";
    private static final String DID_JSON_PATH = "/did.json";
    private static final String WELL_KNOWN_PATH = "/.well-known" + DID_JSON_PATH;

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    @Override
    public boolean isSupportedId(String clientId) {
        return clientId != null && clientId.startsWith(DID_WEB_PREFIX);
    }

    @Override
    public CompletableFuture<PublicKey> getPublicKey(String clientId, SignedJWT jwt) {
        if (!isSupportedId(clientId)) {
            throw new ClientResolutionException(String.format("The client %s is not a supported type.", clientId));
        }
        String identifierPart = clientId.replaceFirst(DID_WEB_PREFIX, "");
        boolean containsPath = identifierPart.contains(":");
        // according to https://w3c-ccg.github.io/did-method-web/#create-register
        if (containsPath) {
            // build path and append did.json
            identifierPart = identifierPart.replaceAll(":", "/") + DID_JSON_PATH;
        } else {
            // take the host and append .well-known/did.json
            identifierPart = identifierPart + WELL_KNOWN_PATH;
        }
        HttpRequest wellKnownRequest = HttpRequest.newBuilder(URI.create("https://" + identifierPart)).GET().build();
        return httpClient.sendAsync(wellKnownRequest, asJson(objectMapper, DidDocument.class))
                .thenApply(response -> {
                    if (response.statusCode() == 200) {
                        return response.body(); // success path
                    } else {
                        throw new BadGatewayException(
                                String.format("Was not able to retrieve did document for %s - status: %s",
                                        clientId,
                                        response.statusCode()
                                ));
                    }
                })
                .thenApply(document -> {
                    if (document == null) {
                        throw new ClientResolutionException(String.format("Was not able to get a did-document from %s.", clientId));
                    }
                    if (!document.getId().equals(clientId)) {
                        log.debug("The did document {} contains a different id({}) than requested: {}.", document, document.getId(), clientId);
                        throw new ClientResolutionException("The DidDocument contains an invalid id.");
                    }
                    return getKeyFromDidDocument(jwt.getHeader().getKeyID(), document);
                });
    }

    private PublicKey getKeyFromDidDocument(String keyId, DidDocument didDocument) {
        if (didDocument.getVerificationMethod() == null) {
            log.debug("The document {} does not contain verification methods.", didDocument);
            throw new ClientResolutionException("The document does not contain verification methods.");
        }
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
            if (jwk.getKeyUse() != KeyUse.SIGNATURE) {
                log.debug("The key-use of the jwk {} is not signature.", jwk);
                throw new ClientResolutionException("The referenced key cannot be used for signatures.");
            }
            return switch (jwk.getKeyType().getValue()) {
                case "RSA" -> ((RSAKey) jwk).toPublicKey();
                case "EC" -> ((ECKey) jwk).toPublicKey();
                case "OKP" -> fromEd25519Jwk((OctetKeyPair) jwk);
                default -> throw new IllegalArgumentException("Unsupported key type: " + jwk.getKeyType());
            };
        } catch (ParseException e) {
            log.debug("Was not able to parse the publicKeyJwt in {} at {}.", didDocument, keyId, e);
            throw new ClientResolutionException("Was not able to parse the publicKeyJwt.", e);
        } catch (JOSEException e) {
            log.debug("Was not able to parse the key in {} at {}.", didDocument, keyId, e);
            throw new ClientResolutionException("Was not able to correctly parse the key.", e);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
            log.debug("Failed to parse ed25519 key from JWK in {} at {}.", didDocument, keyId, e);
            throw new ClientResolutionException(String.format("Failed to parse octet key at %s.", keyId), e);
        }
    }

    private static PublicKey fromEd25519Jwk(OctetKeyPair jwk) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        byte[] raw = jwk.getX().decode();
        byte[] encoded = new byte[]{
                0x30, 0x2A,
                0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
                0x03, 0x21, 0x00
        };
        encoded = concat(encoded, raw);

        KeyFactory kf = KeyFactory.getInstance("Ed25519", "BC");
        return kf.generatePublic(new X509EncodedKeySpec(encoded));
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
