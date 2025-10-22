package io.github.wistefan.oid4vp.client;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.SignedJWT;
import io.github.wistefan.oid4vp.exception.ClientResolutionException;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

public class X509SanDnsClientResolverTest extends ClientResolverTest {

    private X509SanDnsClientResolver x509SanDnsClientResolver;

    @BeforeAll
    public static void addBouncyCastler() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    public void setUp() throws Exception {
        x509SanDnsClientResolver = new X509SanDnsClientResolver();
    }

    private static CertChain generateCertChain(List<String> sans) throws Exception {
        KeyPair rootKeyPair = getECKey();
        KeyPair intermediateKeyPair = getECKey();
        KeyPair leafKeyPair = getECKey();

        X509Certificate rootCA = createRootCA(rootKeyPair);
        X509Certificate intermediateCertificate = createIntermediate(intermediateKeyPair, rootCA, rootKeyPair);
        X509Certificate leafCertificate = createLeaf(leafKeyPair, intermediateCertificate, intermediateKeyPair, sans);
        return new CertChain(rootCA, intermediateCertificate, leafCertificate, rootKeyPair, intermediateKeyPair, leafKeyPair);
    }

    @DisplayName("x509_san_dns should be correctly identified.")
    @ParameterizedTest
    @ValueSource(strings = {"x509_san_dns:test.io", "x509_san_dns:some-other-address.org"})
    public void testIsSupported(String clientId) {
        assertTrue(x509SanDnsClientResolver.isSupportedId(clientId), "The given id should be supported.");
    }

    @DisplayName("Only x509_san_dns should be supported.")
    @ParameterizedTest
    @ValueSource(strings = {"did:jwk:eISomething", "z6MknYNDRL2s1KhzfoPM7PJmH56XmfuAPnMu2AFTEXbouvXE", "key:z6MknYNDRL2s1KhzfoPM7PJmH56XmfuAPnMu2AFTEXbouvXE", "did:key:z6MknyInvalid", "did:key:something-invalid", "did:web", "web:something.org", "something.org"})
    public void testIsNotSupported(String clientId) {
        assertFalse(x509SanDnsClientResolver.isSupportedId(clientId), "The given id should not be supported.");
    }

    @DisplayName("The public key should be retrieved from the x5c.")
    @ParameterizedTest
    @MethodSource("provideIdsAndSan")
    public void testGetPublicKey(String clientId, List<Base64> x5c, CertChain certChain) throws Exception {
        SignedJWT signedJWT = mockSignedJWT(x5c);

        x509SanDnsClientResolver = new X509SanDnsClientResolver(Set.of(new TrustAnchor(certChain.root, null)), false);

        assertEcKeysEqual(x509SanDnsClientResolver.getPublicKey(clientId, signedJWT).get(), certChain.leafKey.getPublic());
    }

    @DisplayName("An error should be thrown, if no valid key can be retrieved.")
    @ParameterizedTest(name = "{index} - {3}")
    @MethodSource("provideInvalidChains")
    public void testGetPublicKeyError(String clientId, List<Base64> certChain, TrustAnchor trustAnchor, String message) {
        SignedJWT signedJWT = mockSignedJWT(certChain);
        x509SanDnsClientResolver = new X509SanDnsClientResolver(Set.of(trustAnchor), false);

        assertThrows(ClientResolutionException.class, () -> x509SanDnsClientResolver.getPublicKey(clientId, signedJWT), message);
    }

    public static Stream<Arguments> provideInvalidChains() throws Exception {
        CertChain noSanChain = generateCertChain(List.of());
        CertChain differentSanChain = generateCertChain(List.of("other-address.io"));
        CertChain testIoChain = generateCertChain(List.of("test.io"));
        List<Base64> noLeafChain = new ArrayList<>(testIoChain.asX5c().subList(1, 3));
        List<Base64> noIntermediateChain = new ArrayList<>(testIoChain.asX5c());
        noIntermediateChain.remove(1);

        return Stream.of(
                Arguments.of("x509_san_dns:test.io", noSanChain.asX5c(), new TrustAnchor(noSanChain.root, null),
                        "If no san is provided, a ClientResolutionException should be thrown."),
                Arguments.of("x509_san_dns:test.io", differentSanChain.asX5c(), new TrustAnchor(differentSanChain.root, null),
                        "If the client san is not included, a ClientResolutionException should be thrown."),
                Arguments.of("x509_san_dns:test.io", testIoChain.asX5c(), new TrustAnchor(differentSanChain.root, null),
                        "If the chain is not rooted in a trust-anchor, a ClientResolutionException should be thrown."),
                Arguments.of("x509_san_dns:test.io", testIoChain.asX5c(), new TrustAnchor(differentSanChain.root, null),
                        "If the chain is not rooted in a trust-anchor, a ClientResolutionException should be thrown."),
                Arguments.of("x509_san_dns:test.io", List.of(), new TrustAnchor(testIoChain.root, null),
                        "If no x5c is provided, a ClientResolutionException should be thrown."),
                Arguments.of("x509_san_dns:test.io", noLeafChain, new TrustAnchor(testIoChain.root, null),
                        "If the chain does not contain a leaf cert, a ClientResolutionException should be thrown."),
                Arguments.of("x509_san_dns:test.io", noIntermediateChain, new TrustAnchor(testIoChain.root, null),
                        "If the chain does not contain an intermediate cert, a ClientResolutionException should be thrown.")
        );
    }

    private static SignedJWT mockSignedJWT(List<Base64> certChain) {
        SignedJWT signedJWT = mock(SignedJWT.class);
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .x509CertChain(certChain)
                .build();
        lenient().when(signedJWT.getHeader()).thenReturn(jwsHeader);
        return signedJWT;
    }


    public static Stream<Arguments> provideIdsAndSan() throws Exception {
        CertChain certChainTestIo = generateCertChain(List.of("test.io"));
        List<Base64> fullChain = certChainTestIo.asX5c();
        List<Base64> noRootChain = new ArrayList<>(certChainTestIo.asX5c().subList(0, 2));

        CertChain certChainMultiSan1 = generateCertChain(List.of("test.io", "another.san"));
        CertChain certChainMultiSan2 = generateCertChain(List.of("another.san", "test.io"));

        return Stream.of(
                Arguments.of("x509_san_dns:test.io", fullChain, certChainTestIo),
                Arguments.of("x509_san_dns:test.io", noRootChain, certChainTestIo),
                Arguments.of("x509_san_dns:test.io", certChainMultiSan1.asX5c(), certChainMultiSan1),
                Arguments.of("x509_san_dns:test.io", certChainMultiSan2.asX5c(), certChainMultiSan2)
        );

    }

    public static X509Certificate createRootCA(KeyPair keyPair) throws Exception {
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 1000L * 60 * 60);
        Date notAfter = new Date(now + 3650L * 24 * 60 * 60 * 1000); // 10 years

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                new org.bouncycastle.asn1.x500.X500Name("CN=RootCA"),
                BigInteger.valueOf(now),
                notBefore,
                notAfter,
                new org.bouncycastle.asn1.x500.X500Name("CN=RootCA"),
                keyPair.getPublic()
        );

        // Add basic constraints for CA
        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true,
                new org.bouncycastle.asn1.x509.BasicConstraints(true));

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certBuilder.build(
                        new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(keyPair.getPrivate())
                ));
    }

    public static X509Certificate createIntermediate(KeyPair intermediateKP, X509Certificate issuerCert, KeyPair issuerKP) throws Exception {
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 1000L * 60 * 60);
        Date notAfter = new Date(now + 3650L * 24 * 60 * 60 * 1000);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerCert,
                BigInteger.valueOf(now + 1),
                notBefore,
                notAfter,
                new org.bouncycastle.asn1.x500.X500Name("CN=Intermediate"),
                intermediateKP.getPublic()
        );

        // Mark as CA
        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true,
                new org.bouncycastle.asn1.x509.BasicConstraints(1));

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certBuilder.build(
                        new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(issuerKP.getPrivate())
                ));
    }

    public static X509Certificate createLeaf(KeyPair leafKP, X509Certificate issuerCert, KeyPair issuerKP, List<String> dnsSAN) throws Exception {
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 1000L * 60 * 60);
        Date notAfter = new Date(now + 365L * 24 * 60 * 60 * 1000); // 1 year

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerCert,
                BigInteger.valueOf(now + 2),
                notBefore,
                notAfter,
                new org.bouncycastle.asn1.x500.X500Name("CN=Leaf"),
                leafKP.getPublic()
        );

        GeneralName[] generalNames = dnsSAN.stream()
                .map(san -> new GeneralName(GeneralName.dNSName, san))
                .toArray(GeneralName[]::new);
        // Add SAN
        GeneralNames subjectAltName = new GeneralNames(generalNames);
        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false, subjectAltName);

        // Not a CA
        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new org.bouncycastle.asn1.x509.BasicConstraints(false));

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certBuilder.build(
                        new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(issuerKP.getPrivate())
                ));
    }

    private record CertChain(X509Certificate root, X509Certificate intermediate, X509Certificate leaf, KeyPair rootKey,
                             KeyPair intermediateKey, KeyPair leafKey) {
        public X509Certificate[] asChain() {
            return new X509Certificate[]{leaf, intermediate, root};
        }

        public List<Base64> asX5c() {
            return Arrays.stream(asChain())
                    .map(c -> {
                        try {
                            return Base64.encode(c.getEncoded());
                        } catch (CertificateEncodingException e) {
                            throw new RuntimeException(e);
                        }
                    })
                    .toList();
        }

        ;
    }
}