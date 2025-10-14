package io.github.wistefan.oid4vp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import io.github.wistefan.dcql.*;
import io.github.wistefan.dcql.model.CredentialFormat;
import io.github.wistefan.dcql.model.TrustedAuthorityType;
import io.github.wistefan.oid4vp.client.DidWebClientResolver;
import io.github.wistefan.oid4vp.client.X509SanDnsClientResolver;
import io.github.wistefan.oid4vp.config.HolderConfiguration;
import io.github.wistefan.oid4vp.config.RequestParameters;
import io.github.wistefan.oid4vp.credentials.CredentialsRepository;
import io.github.wistefan.oid4vp.credentials.FileSystemCredentialsRepository;
import io.github.wistefan.oid4vp.mapping.CredentialFormatDeserializer;
import io.github.wistefan.oid4vp.mapping.TrustedAuthorityTypeDeserializer;
import io.github.wistefan.oid4vp.model.TokenResponse;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class ClientTest {

    @Test
    public void didWebTest() throws Exception {

        HttpClient httpClient = HttpClient.newHttpClient();
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
        DidWebClientResolver didWebClientResolver = new DidWebClientResolver(httpClient, objectMapper);
        PublicKey pk = didWebClientResolver
                .getPublicKey(
                        "did:web:www.linkedin.com",
                        SignedJWT.parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"))
                .get();

    }

    @Test
    public void test() throws Exception {
        Set<TrustAnchor> trustAnchors = loadCertificates("secret/test-ca.pem")
                .stream()
                .map(c -> new TrustAnchor(c, null))
                .collect(Collectors.toSet());

        String did = "did:key:zDnaehXH4gDLjLeWcACPyQX9TnvsKiQNt6KT7fdsfyW6fhEYA";
        PrivateKey privateKey = loadPrivateKey("EC", "secret/private-key.pem");
        HolderConfiguration holderConfiguration = new HolderConfiguration(
                URI.create(did),
                did,
                JWEAlgorithm.ECDH_ES,
                privateKey
        );

        RequestParameters requestParameters = new RequestParameters(URI.create("http://contract-management.127.0.0.1.nip.io"),
                "",
                "data-service",
                Set.of("legal"));

        HttpClient httpClient = createInsecureHttpClient();
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

        OID4VPClient client = new OID4VPClient(httpClient, holderConfiguration, objectMapper, List.of(new X509SanDnsClientResolver(trustAnchors, false)), dcqlEvaluator, credentialsRepository, signingService);
        String jwtString = client.getAccessToken(requestParameters).thenApply(TokenResponse::getAccessToken).get();

        SignedJWT signedJWT = SignedJWT.parse(jwtString);
        assertNotNull(signedJWT.getJWTClaimsSet().getClaim("verifiableCredential"));
    }


    public static HttpClient createInsecureHttpClient() throws Exception {
        // 1. Disable certificate validation
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    }
                }
        };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, new SecureRandom());

        // 2. Set proxy
        ProxySelector proxySelector = ProxySelector.of(new InetSocketAddress("localhost", 8888));

        // 3. Build HttpClient
        return HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .sslContext(sslContext)
                .proxy(proxySelector)
                .build();
    }

    public static PrivateKey loadPrivateKey(String keyType, String filename) throws Exception {
        try (InputStream is = ClientTest.class.getClassLoader().getResourceAsStream(filename)) {
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

    public static List<X509Certificate> loadCertificates(String resource) throws Exception {

        try (InputStream is = ClientTest.class.getClassLoader().getResourceAsStream(resource)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certs = cf.generateCertificates(is);

            List<X509Certificate> list = new ArrayList<>();
            for (Certificate cert : certs) {
                list.add((X509Certificate) cert);
            }
            return list;
        }
    }
}
