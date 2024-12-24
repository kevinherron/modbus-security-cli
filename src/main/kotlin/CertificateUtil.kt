import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERUTF8String
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.util.*


fun generateCaCertificate(): Pair<KeyPair, X509Certificate> {
    try {
        val generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(2048)
        val keyPair: KeyPair = generator.generateKeyPair()

        val nameBuilder = X500NameBuilder(BCStyle.INSTANCE)
        nameBuilder.addRDN(BCStyle.CN, "Modbus CA")
        val name: X500Name = nameBuilder.build()

        val certificateBuilder = X509v3CertificateBuilder(
            name,
            BigInteger(System.currentTimeMillis().toString()),
            Date(),
            Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L),
            Locale.ENGLISH,
            name,
            SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
        )

        // Basic Constraints
        val basicConstraints = BasicConstraints(true)
        certificateBuilder.addExtension(Extension.basicConstraints, true, basicConstraints)

        // Key Usage
        certificateBuilder.addExtension(
            Extension.keyUsage,
            true,
            KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign)
        )

        // Authority Key Identifier
        certificateBuilder.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            JcaX509ExtensionUtils()
                .createAuthorityKeyIdentifier(keyPair.public)
        )

        // Subject Key Identifier
        certificateBuilder.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            JcaX509ExtensionUtils()
                .createSubjectKeyIdentifier(keyPair.public)
        )

        val contentSigner = JcaContentSignerBuilder("SHA256withRSA")
            .setProvider(BouncyCastleProvider())
            .build(keyPair.private)

        val certificate: X509Certificate =
            JcaX509CertificateConverter()
                .getCertificate(certificateBuilder.build(contentSigner))

        return Pair(keyPair, certificate)
    } catch (e: Exception) {
        throw RuntimeException(e)
    }
}

fun generateCaSignedCertificate(
    authorityKeyPair: Pair<KeyPair, X509Certificate>,
    client: Boolean,
    clientRole: String? = null
): Pair<KeyPair, X509Certificate> {

    val generator = KeyPairGenerator.getInstance("RSA")
    generator.initialize(2048)
    val keyPair = generator.generateKeyPair()

    val nameBuilder = X500NameBuilder()
    if (client) {
        nameBuilder.addRDN(BCStyle.CN, "Modbus Client")
    } else {
        nameBuilder.addRDN(BCStyle.CN, "Modbus Server")
    }
    val name = nameBuilder.build()

    val certSerialNumber = BigInteger(System.currentTimeMillis().toString())

    val certificateBuilder = X509v3CertificateBuilder(
        X500Name(authorityKeyPair.second.getSubjectX500Principal().name),
        certSerialNumber,
        Date(),
        Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L),
        name,
        SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
    )

    // Basic Constraints
    val basicConstraints = BasicConstraints(false)
    certificateBuilder.addExtension(Extension.basicConstraints, false, basicConstraints)

    // Key Usage
    certificateBuilder.addExtension(
        Extension.keyUsage,
        true,
        KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment)
    )

    // Authority Key Identifier
    certificateBuilder.addExtension(
        Extension.authorityKeyIdentifier,
        false,
        JcaX509ExtensionUtils()
            .createAuthorityKeyIdentifier(authorityKeyPair.second)
    )

    // Subject Key Identifier
    certificateBuilder.addExtension(
        Extension.subjectKeyIdentifier,
        false,
        JcaX509ExtensionUtils()
            .createSubjectKeyIdentifier(keyPair.public)
    )

    if (client) {
        // EKU Client Authentication
        certificateBuilder.addExtension(
            Extension.extendedKeyUsage,
            false,
            ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth)
        )

        // Modbus Security Role OID
        if (clientRole != null) {
            certificateBuilder.addExtension(
                ASN1ObjectIdentifier("1.3.6.1.4.1.50316.802.1"),
                false,
                DERUTF8String(clientRole)
            )
        }
    } else {
        // EKU Server Authentication
        certificateBuilder.addExtension(
            Extension.extendedKeyUsage,
            false,
            ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth)
        )

        // Subject Alternative Name
        certificateBuilder.addExtension(
            Extension.subjectAlternativeName,
            false,
            GeneralNames(arrayOf(GeneralName(GeneralName.dNSName, "localhost")))
        )
    }

    val contentSigner = JcaContentSignerBuilder("SHA256withRSA")
        .setProvider(BouncyCastleProvider())
        .build(authorityKeyPair.first.private)

    val certificate: X509Certificate =
        JcaX509CertificateConverter()
            .getCertificate(certificateBuilder.build(contentSigner))

    return Pair(keyPair, certificate)
}
