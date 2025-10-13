package io.github.wistefan.oid4vp.client;

import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.SignedJWT;
import io.github.wistefan.oid4vp.exception.ClientResolutionException;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import reactor.core.publisher.Mono;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.util.*;

public class X509SanDnsClientResolver implements ClientResolver {

    private static final String CACERTS_PATH = System.getProperty("javax.net.ssl.trustStore",
            System.getProperty("java.home") + "/lib/security/cacerts");
    private static final char[] DEFAULT_TRUSTSTORE_PASSWORD = System.getProperty(
            "javax.net.ssl.trustStorePassword", "changeit").toCharArray();

    private static final String X5C_HEADER = "x5c";
    private static final String X509_SANS_SCHEME = "x509_san_dns";
    private static final String X509_HASH = "x509_hash";
    private static final String DECENTRALIZED_IDENTIFIER_SCHEME = "decentralized_identifier";

    private final Set<TrustAnchor> trustAnchors;
    private final boolean enableRevocation;


    public X509SanDnsClientResolver(Set<TrustAnchor> trustAnchors, boolean enableRevocation) {
        this.trustAnchors = trustAnchors;
        this.enableRevocation = enableRevocation;
    }

    public X509SanDnsClientResolver(Set<TrustAnchor> trustAnchors) {
        this.trustAnchors = trustAnchors;
        this.enableRevocation = true;
    }

    public X509SanDnsClientResolver() {
        try {
            this.trustAnchors = getTrustAnchors();
            this.enableRevocation = true;
        } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new ClientResolutionException("Was not able to intialize the client-resolver, cannot read system trust store.", e);
        }
    }

    @Override
    public boolean isSupportedId(String clientId) {
        return clientId.startsWith(X509_SANS_SCHEME);
    }

    @Override
    public Mono<PublicKey> getPublicKey(String clientId, SignedJWT jwt) {
        List<X509Certificate> x509Certificates = getX509List(jwt.getHeader().getX509CertChain());
        if (!isValid(x509Certificates)) {
            throw new ClientResolutionException("Received an untrusted x5c-header.");
        }

        X509Certificate leafCertificate = x509Certificates.stream()
                .filter(this::isLeaf)
                .findAny().orElseThrow(() -> new ClientResolutionException("No leaf certificate was included in the x5c."));
        if (!containsAsSan(leafCertificate, getDNSFromId(clientId))) {
            throw new ClientResolutionException("The client is not contain in the SAN of the x5c.");
        }
        return Mono.just(leafCertificate.getPublicKey());
    }

    private String getDNSFromId(String clientId) {
        return clientId
                .replaceFirst(X509_SANS_SCHEME, "")
                .replaceFirst(":", "");
    }

    private boolean containsAsSan(X509Certificate certificate, String dns) {
        try {
            X509CertificateHolder certificateHolder = new JcaX509CertificateHolder(certificate);
            GeneralNames sanNames = GeneralNames.fromExtensions(
                    certificateHolder.getExtensions(),
                    org.bouncycastle.asn1.x509.Extension.subjectAlternativeName
            );
            return Arrays.stream(sanNames.getNames())
                    // works for dns -> enough to fulfill x509_san_dns, if it's an ip it would fail
                    .map(GeneralName::getName)
                    .map(Object::toString)
                    .anyMatch(dns::equals);
        } catch (CertificateEncodingException e) {
            throw new ClientResolutionException("Was not able to wrap the certificate.", e);
        }
    }

    private boolean isValid(List<X509Certificate> certificateChain) {
        try {
            PKIXParameters params = new PKIXParameters(trustAnchors);
            params.setRevocationEnabled(enableRevocation);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CertPath certPath = cf.generateCertPath(certificateChain);

            CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) certPathValidator.validate(certPath, params);
            return result.getTrustAnchor() != null;
        } catch (CertificateException | NoSuchAlgorithmException |
                 CertPathValidatorException | InvalidAlgorithmParameterException e) {
            throw new ClientResolutionException("Was not able to validate the x5c.", e);
        }
    }

    private List<X509Certificate> getX509List(List<Base64> x5cList) {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            return x5cList.stream()
                    .map(Base64::decode)
                    .map(ByteArrayInputStream::new)
                    .map(arrayInput -> {
                        try {
                            return certificateFactory.generateCertificate(arrayInput);
                        } catch (CertificateException e) {
                            throw new ClientResolutionException("Was not able to decode x5c-header.", e);
                        }
                    })
                    .filter(X509Certificate.class::isInstance)
                    .map(X509Certificate.class::cast)
                    .toList();

        } catch (CertificateException e) {
            throw new ClientResolutionException("Was not able to instantiate CertificateFactory.", e);
        }
    }

    private boolean isLeaf(X509Certificate certificate) {

        try {
            X509CertificateHolder certificateHolder = new JcaX509CertificateHolder(certificate);
            if (certificateHolder.getExtensions() != null) {
                org.bouncycastle.asn1.x509.BasicConstraints bc = org.bouncycastle.asn1.x509.BasicConstraints.fromExtensions(
                        certificateHolder.getExtensions()
                );
                if (bc != null && bc.isCA()) {
                    return false; // It's a CA
                }
            }
            // Check if self-signed
            return !certificateHolder.getSubject().equals(certificateHolder.getIssuer());
        } catch (CertificateEncodingException e) {
            throw new ClientResolutionException("Was not able to wrap the certificate.", e);
        }

    }

    /**
     * Reads the system truststore into a TrustAnchor Set to be used by the resolver.
     */
    public static Set<TrustAnchor> getTrustAnchors() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream in = new FileInputStream(CACERTS_PATH)) {
            trustStore.load(in, DEFAULT_TRUSTSTORE_PASSWORD);
        }

        Set<TrustAnchor> anchors = new HashSet<>();
        Enumeration<String> aliases = trustStore.aliases();
        while (aliases.hasMoreElements()) {
            Certificate cert = trustStore.getCertificate(aliases.nextElement());
            if (cert instanceof X509Certificate) {
                anchors.add(new TrustAnchor((X509Certificate) cert, null));
            }
        }
        return anchors;
    }

}
