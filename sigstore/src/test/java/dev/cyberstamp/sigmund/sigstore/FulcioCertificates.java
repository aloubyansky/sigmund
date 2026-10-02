package dev.cyberstamp.sigmund.sigstore;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Builds self-signed certificates shaped like Fulcio's: a subject alternative name, the OIDC
 * issuer in the V2 issuer extension, and Fulcio extensions encoded as UTF-8 strings.
 */
final class FulcioCertificates {

    private static final String FULCIO_OID_PREFIX = "1.3.6.1.4.1.57264.1.";
    private static final String ISSUER_V2 = "8";

    private FulcioCertificates() {
    }

    /**
     * Creates a certificate.
     *
     * @param issuer the OIDC issuer, or {@code null} to leave the issuer extension out
     * @param subject the subject alternative name
     * @param extensions Fulcio extension values keyed by OID suffix, such as {@code "12"}
     * @return the certificate
     * @throws Exception if the certificate cannot be built
     */
    static X509Certificate create(String issuer, GeneralName subject,
            Map<String, String> extensions) throws Exception {
        KeyPair keys = KeyPairGenerator.getInstance("EC").generateKeyPair();
        Instant now = Instant.now();
        X500Name name = new X500Name("CN=sigstore-test");
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                Date.from(now), Date.from(now.plus(Duration.ofMinutes(10))), name, keys.getPublic());
        builder.addExtension(Extension.subjectAlternativeName, true, new GeneralNames(subject));
        if (issuer != null) {
            addFulcioExtension(builder, ISSUER_V2, issuer);
        }
        for (Map.Entry<String, String> extension : extensions.entrySet()) {
            addFulcioExtension(builder, extension.getKey(), extension.getValue());
        }
        return new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate())));
    }

    private static void addFulcioExtension(X509v3CertificateBuilder builder, String suffix,
            String value) throws Exception {
        builder.addExtension(new ASN1ObjectIdentifier(FULCIO_OID_PREFIX + suffix), false,
                new DERUTF8String(value));
    }
}
