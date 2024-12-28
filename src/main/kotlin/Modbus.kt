import cmd.Client
import cmd.ModbusCmd
import cmd.Server
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.core.subcommands
import util.createOrLoadKeyStore
import util.generateCaCertificate
import util.generateCaSignedCertificate
import util.getKeys
import java.nio.file.Path
import java.security.KeyStore


fun main(args: Array<String>) {
    createOrLoadKeyStores()

    val command = ModbusCmd().subcommands(
        Server(),
        Client().subcommands(Client.Rhr(), Client.Wsr())
    )

    command.main(args)
}

private fun createOrLoadKeyStores() {
    val authorityKeyStore: KeyStore =
        createOrLoadKeyStore(Path.of("./pki/ca.pfx"), "ca") {
            generateCaCertificate()
        }

    createOrLoadKeyStore(Path.of("./pki/server.pfx"), "server") {
        val authorityKeys = authorityKeyStore.getKeys("ca")
        generateCaSignedCertificate(authorityKeys, false)
    }

    createOrLoadKeyStore(Path.of("./pki/client1.pfx"), "client1") {
        val authorityKeys = authorityKeyStore.getKeys("ca")
        generateCaSignedCertificate(authorityKeys, true, "ReadOnly")
    }

    createOrLoadKeyStore(Path.of("./pki/client2.pfx"), "client2") {
        val authorityKeys = authorityKeyStore.getKeys("ca")
        generateCaSignedCertificate(authorityKeys, true, "ReadWrite")
    }
}

