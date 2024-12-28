import cmd.ModbusSecurityServer
import com.digitalpetri.modbus.client.ModbusTcpClient
import com.digitalpetri.modbus.exceptions.ModbusException
import com.digitalpetri.modbus.pdu.ReadCoilsRequest
import com.digitalpetri.modbus.pdu.WriteSingleCoilRequest
import com.digitalpetri.modbus.tcp.client.NettyTcpClientTransport
import org.junit.jupiter.api.*
import util.*
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore

class ModbusCmdSecurityServerTest {

    private val pkiPath: Path = Files.createTempDirectory("pki")

    private val authorityKeyStore: KeyStore =
        createOrLoadKeyStore(pkiPath.resolve("ca.pfx"), "ca") {
            generateCaCertificate()
        }

    init {
        pkiPath.toFile().deleteOnExit()

        createOrLoadKeyStore(pkiPath.resolve("server.pfx"), "server") {
            val authorityKeys = authorityKeyStore.getKeys("ca")
            generateCaSignedCertificate(authorityKeys, false)
        }
    }

    @BeforeEach
    fun setUp() {
        ModbusSecurityServer.start(
            pkiPath.resolve("ca.pfx"),
            pkiPath.resolve("server.pfx")
        )
    }

    @AfterEach
    fun tearDown() {
        ModbusSecurityServer.stop()
    }

    @Test
    fun readOnlyClient() {
        val clientKeyStore = createOrLoadKeyStore(pkiPath.resolve("client.pfx"), "client") {
            val authorityKeys = authorityKeyStore.getKeys("ca")
            generateCaSignedCertificate(authorityKeys, true, "ReadOnly")
        }

        val client = ModbusTcpClient.create(
            NettyTcpClientTransport.create {
                it.hostname = "localhost"
                it.port = 802

                it.tlsEnabled = true
                it.keyManagerFactory = clientKeyStore.toKeyManagerFactory()
                it.trustManagerFactory = authorityKeyStore.toTrustManagerFactory()
            }
        )

        try {
            client.connect()

            assertDoesNotThrow {
                client.readCoils(1, ReadCoilsRequest(0, 1))
            }

            assertThrows<ModbusException> {
                client.writeSingleCoil(1, WriteSingleCoilRequest(0, true))
            }
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun readWriteClient() {
        val clientKeyStore = createOrLoadKeyStore(pkiPath.resolve("client.pfx"), "client") {
            val authorityKeys = authorityKeyStore.getKeys("ca")
            generateCaSignedCertificate(authorityKeys, true, "ReadWrite")
        }

        val client = ModbusTcpClient.create(
            NettyTcpClientTransport.create {
                it.hostname = "localhost"
                it.port = 802

                it.tlsEnabled = true
                it.keyManagerFactory = clientKeyStore.toKeyManagerFactory()
                it.trustManagerFactory = authorityKeyStore.toTrustManagerFactory()
            }
        )

        try {
            client.connect()

            assertDoesNotThrow {
                client.readCoils(1, ReadCoilsRequest(0, 1))
                client.writeSingleCoil(1, WriteSingleCoilRequest(0, true))
            }
        } finally {
            client.disconnect()
        }
    }

}
