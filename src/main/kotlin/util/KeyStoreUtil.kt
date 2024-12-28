package util

import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator
import java.nio.file.Path
import java.security.KeyPair
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.TrustManagerFactory
import kotlin.io.path.exists
import kotlin.io.path.inputStream
import kotlin.io.path.outputStream


fun KeyStore.getKeys(
    alias: String,
    password: CharArray = CharArray(0)
): Pair<KeyPair, X509Certificate> {

    val certificate = getCertificate(alias) as X509Certificate
    val publicKey: PublicKey = certificate.publicKey
    val privateKey = getKey(alias, password) as PrivateKey

    return Pair(KeyPair(publicKey, privateKey), certificate)
}

fun KeyStore.toKeyManagerFactory(password: CharArray = CharArray(0)): KeyManagerFactory {
    return KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
        init(this@toKeyManagerFactory, password)
    }
}

fun KeyStore.toTrustManagerFactory(): TrustManagerFactory {
    return TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
        init(this@toTrustManagerFactory)
    }
}

fun createOrLoadKeyStore(
    path: Path,
    alias: String,
    password: CharArray = CharArray(0),
    createKeys: () -> Pair<KeyPair, X509Certificate>
): KeyStore {

    return if (path.toFile().exists()) {
        KeyStore.getInstance("PKCS12").apply {
            load(path.inputStream(), password)
        }
    } else {
        // create parent pki dirs if needed
        if (!path.parent.exists()) {
            assert(path.parent.toFile().mkdirs())
        }

        val keys: Pair<KeyPair, X509Certificate> = createKeys()

        keys.writeToFiles(path.parent, alias)

        KeyStore.getInstance("PKCS12").apply {
            load(null, password)
            setKeyEntry(alias, keys.first.private, password, arrayOf(keys.second))
            store(path.outputStream(), password)
        }
    }
}

private fun Pair<KeyPair, X509Certificate>.writeToFiles(path: Path, name: String) {
    writePrivateKeyToFile(first, path.resolve("$name.key"))
    writeCertificateToFile(second, path.resolve("$name.crt"))
}

private fun writePrivateKeyToFile(keyPair: KeyPair, path: Path) {
    JcaPEMWriter(path.toFile().writer()).use {
        it.writeObject(JcaPKCS8Generator(keyPair.private, null))
    }
}

private fun writeCertificateToFile(certificate: X509Certificate, path: Path) {
    JcaPEMWriter(path.toFile().writer()).use {
        it.writeObject(certificate)
    }
}
