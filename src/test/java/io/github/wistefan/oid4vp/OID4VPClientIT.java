package io.github.wistefan.oid4vp;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import io.github.wistefan.dcql.*;
import io.github.wistefan.dcql.model.CredentialFormat;
import io.github.wistefan.dcql.model.TrustedAuthorityType;
import io.github.wistefan.oid4vp.client.DidKeyClientResolver;
import io.github.wistefan.oid4vp.client.DidWebClientResolver;
import io.github.wistefan.oid4vp.client.X509SanDnsClientResolver;
import io.github.wistefan.oid4vp.config.HolderConfiguration;
import io.github.wistefan.oid4vp.config.RequestParameters;
import io.github.wistefan.oid4vp.credentials.CredentialsRepository;
import io.github.wistefan.oid4vp.credentials.FileSystemCredentialsRepository;
import io.github.wistefan.oid4vp.mapping.CredentialFormatDeserializer;
import io.github.wistefan.oid4vp.mapping.TrustedAuthorityTypeDeserializer;
import io.github.wistefan.oid4vp.model.TokenResponse;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class OID4VPClientIT {

    @BeforeAll
    public static void setupBC() throws IOException, InterruptedException {
        Security.addProvider(new BouncyCastleProvider());

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpRequest tirRequest = HttpRequest.newBuilder(URI.create("http://localhost:8090/issuer"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers
                        .ofString("{\"did\":\"did:key:zDnaeXr3XaSHvXzxdB1Uch5mmznDpaNHBS5WeYZChQr8DGC5t\"}"))
                .build();
        httpClient.send(tirRequest, HttpResponse.BodyHandlers.ofString());

    }

    @ParameterizedTest
    @MethodSource("provideRequests")
    public void test(RequestParameters requestParameters) throws Exception {

        String did = "did:key:zDnaehXH4gDLjLeWcACPyQX9TnvsKiQNt6KT7fdsfyW6fhEYA";
        PrivateKey privateKey = loadPrivateKey("EC", "secret/private-key.pem");
        HolderConfiguration holderConfiguration = new HolderConfiguration(
                URI.create(did),
                did,
                JWEAlgorithm.ECDH_ES,
                privateKey
        );


        HttpClient httpClient = HttpClient.newHttpClient();
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
        SimpleModule deserializerModule = new SimpleModule();
        deserializerModule.addDeserializer(CredentialFormat.class, new CredentialFormatDeserializer());
        deserializerModule.addDeserializer(TrustedAuthorityType.class, new TrustedAuthorityTypeDeserializer());
        objectMapper.registerModule(deserializerModule);
        CredentialsRepository credentialsRepository = new FileSystemCredentialsRepository("/home/stefanw/git/wistefan/oid4vp-client-lib/src/test/resources/test-credentials", objectMapper);

        DCQLEvaluator dcqlEvaluator = new DCQLEvaluator(List.of(
                new JwtCredentialEvaluator(),
                new DcSdJwtCredentialEvaluator(),
                new VcSdJwtCredentialEvaluator(),
                new MDocCredentialEvaluator(),
                new LdpCredentialEvaluator()));

        SigningService signingService = new HolderSigningService(holderConfiguration, objectMapper);
        OID4VPClient client = new OID4VPClient(httpClient, holderConfiguration, objectMapper, List.of(new DidKeyClientResolver()), dcqlEvaluator, credentialsRepository, signingService);

        String jwtString = client.getAccessToken(requestParameters).thenApply(TokenResponse::getAccessToken).get();

        SignedJWT signedJWT = SignedJWT.parse(jwtString);
        assertNotNull(signedJWT.getJWTClaimsSet().getClaim("verifiableCredential"));
    }

    private static Stream<Arguments> provideRequests() {
        return Stream.of(
                Arguments.of(new RequestParameters(URI.create("http://localhost:8080"),
                        "test-service-sd",
                        null,
                        Set.of("openid"))),
                Arguments.of(new RequestParameters(URI.create("http://localhost:8080"),
                        "test-service-jwt",
                        null,
                        Set.of("openid")))
        );
    }

    public static PrivateKey loadPrivateKey(String keyType, String filename) throws Exception {
        try (InputStream is = OID4VPClientIT.class.getClassLoader().getResourceAsStream(filename)) {
            if (is == null) {
                throw new IllegalArgumentException("Resource not found: " + filename);
            }

            // Read PEM file content
            String pem = new String(is.readAllBytes(), StandardCharsets.UTF_8)
                    .replaceAll("-----BEGIN (.*)-----", "")
                    .replaceAll("-----END (.*)-----", "")
                    .replaceAll("\\s", "");

            // Base64 decode
            byte[] decoded = Base64.getDecoder().decode(pem);

            // Build key spec
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
            KeyFactory keyFactory = KeyFactory.getInstance(keyType); // or "EC"
            return keyFactory.generatePrivate(keySpec);
        }
    }
}
