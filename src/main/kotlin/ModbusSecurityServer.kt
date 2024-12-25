import com.digitalpetri.modbus.server.ModbusTcpServer
import com.digitalpetri.modbus.server.ProcessImage
import com.digitalpetri.modbus.server.ReadWriteModbusServices
import com.digitalpetri.modbus.server.authz.AuthzContext
import com.digitalpetri.modbus.server.authz.AuthzHandler.AuthzResult
import com.digitalpetri.modbus.server.authz.AuthzModbusServices
import com.digitalpetri.modbus.server.authz.ReadWriteAuthzHandler
import com.digitalpetri.modbus.tcp.server.NettyTcpServerTransport
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.nio.file.Path
import java.security.KeyStore
import java.util.*
import java.util.function.Consumer


fun main() {
    val authorityKeyStore: KeyStore =
        createOrLoadKeyStore(Path.of("./pki/ca.pfx"), "ca") {
            generateCaCertificate()
        }

    val serverKeyStore: KeyStore =
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

    ModbusSecurityServer.start(authorityKeyStore, serverKeyStore)

    Thread.sleep(Long.MAX_VALUE)
}

object ModbusSecurityServer {

    private val LOGGER: Logger = LoggerFactory.getLogger("ModbusSecurityServer")

    private lateinit var server: ModbusTcpServer

    fun start(authorityKeyStore: KeyStore, serverKeyStore: KeyStore) {
        val transport = NettyTcpServerTransport.create { cfg ->
            cfg.bindAddress = "0.0.0.0"
            cfg.port = 802

            cfg.tlsEnabled = true
            cfg.keyManagerFactory = serverKeyStore.toKeyManagerFactory()
            cfg.trustManagerFactory = authorityKeyStore.toTrustManagerFactory()

            cfg.pipelineCustomizer = Consumer { pipeline ->
                pipeline.addFirst(object : ChannelInboundHandlerAdapter() {
                    override fun channelActive(ctx: ChannelHandlerContext) {
                        LOGGER.info("Connection from: ${ctx.channel().remoteAddress()}")
                    }

                    override fun channelInactive(ctx: ChannelHandlerContext) {
                        LOGGER.info("Connection closed: ${ctx.channel().remoteAddress()}")
                    }
                })
            }
        }

        server = ModbusTcpServer.create(
            transport,
            AuthzModbusServices(AuthzHandler, ModbusServices)
        )

        server.start()

        LOGGER.info("Modbus Security server listening on port 802")
    }

    fun stop() {
        server.stop()
    }

    object ModbusServices : ReadWriteModbusServices() {

        private val processImage = ProcessImage()

        override fun getProcessImage(unitId: Int): Optional<ProcessImage> {
            return Optional.of(processImage)
        }

    }

    object AuthzHandler : ReadWriteAuthzHandler() {

        private const val ROLE_READ_ONLY = "ReadOnly"
        private const val ROLE_READ_WRITE = "ReadWrite"

        override fun authorizeRead(unitId: Int, authzContext: AuthzContext): AuthzResult {
            val result: AuthzResult = authzContext.clientRole()
                .map { role ->
                    when (role) {
                        ROLE_READ_ONLY, ROLE_READ_WRITE -> AuthzResult.AUTHORIZED
                        else -> AuthzResult.NOT_AUTHORIZED
                    }
                }
                .orElse(AuthzResult.NOT_AUTHORIZED)

            LOGGER.info("authorizeRead: role=${authzContext.clientRole()}, result=$result")

            return result
        }

        override fun authorizeWrite(unitId: Int, authzContext: AuthzContext): AuthzResult {
            val result: AuthzResult = authzContext.clientRole()
                .map { role ->
                    when (role) {
                        ROLE_READ_WRITE -> AuthzResult.AUTHORIZED
                        else -> AuthzResult.NOT_AUTHORIZED
                    }
                }
                .orElse(AuthzResult.NOT_AUTHORIZED)

            LOGGER.info("authorizeWrite: role=${authzContext.clientRole()}, result=$result")

            return result
        }

    }

}
