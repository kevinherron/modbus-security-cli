import cmd.ModbusSecurityServer
import io.stepfunc.rodbus.*
import io.stepfunc.rodbus.Nothing
import org.joou.Unsigned.ubyte
import org.joou.Unsigned.ushort
import org.junit.jupiter.api.*
import util.createOrLoadKeyStore
import util.generateCaCertificate
import util.generateCaSignedCertificate
import util.getKeys
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore
import java.time.Duration
import java.util.concurrent.CompletionStage
import java.util.concurrent.LinkedBlockingQueue


class StepfuncInteropTest {

    companion object {

        private val runtime = Runtime(RuntimeConfig().withNumCoreThreads(ushort(4)))

        init {
            Logging.configure(LoggingConfig(), ConsoleLogger())
        }

    }

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
        createOrLoadKeyStore(pkiPath.resolve("client.pfx"), "client") {
            val authorityKeys = authorityKeyStore.getKeys("ca")
            generateCaSignedCertificate(authorityKeys, true, "ReadOnly")
        }

        val tlsConfig = TlsClientConfig(
            "localhost",
            pkiPath.resolve("ca.crt").toAbsolutePath().toString(),
            pkiPath.resolve("client.crt").toAbsolutePath().toString(),
            pkiPath.resolve("client.key").toAbsolutePath().toString(),
            ""
        )

        val queue = LinkedBlockingQueue<ClientState>()

        val channel = ClientChannel.createTls(
            runtime,
            "localhost",
            ushort(802),
            ushort(100),
            RetryStrategy(),
            tlsConfig,
            DecodeLevel.nothing(),
            TestClientStateListener(queue)
        )

        try {
            channel.enable()
            awaitConnectedState(queue)

            assertDoesNotThrow {
                val cs: CompletionStage<List<BitValue>> = channel.readCoils(
                    RequestParam(ubyte(1), Duration.ofSeconds(2)),
                    AddressRange(ushort(0), ushort(1))
                )
                val values: List<BitValue> = cs.toCompletableFuture().join()
                println(values.joinToString { "i=${it.index}, v=${it.value}" })
            }

            assertThrows<Exception> {
                val cs: CompletionStage<Nothing> = channel.writeSingleCoil(
                    RequestParam(ubyte(1), Duration.ofSeconds(2)),
                    BitValue(ushort(0), true)
                )
                cs.toCompletableFuture().join()
            }
        } finally {
            channel.disable()
            channel.shutdown()
        }
    }

    @Test
    fun readWriteClient() {
        createOrLoadKeyStore(pkiPath.resolve("client.pfx"), "client") {
            val authorityKeys = authorityKeyStore.getKeys("ca")
            generateCaSignedCertificate(authorityKeys, true, "ReadWrite")
        }

        val tlsConfig = TlsClientConfig(
            "localhost",
            pkiPath.resolve("ca.crt").toAbsolutePath().toString(),
            pkiPath.resolve("client.crt").toAbsolutePath().toString(),
            pkiPath.resolve("client.key").toAbsolutePath().toString(),
            ""
        )

        val queue = LinkedBlockingQueue<ClientState>()

        val channel = ClientChannel.createTls(
            runtime,
            "localhost",
            ushort(802),
            ushort(100),
            RetryStrategy(),
            tlsConfig,
            DecodeLevel.nothing(),
            TestClientStateListener(queue)
        )

        try {
            channel.enable()
            awaitConnectedState(queue)

            assertDoesNotThrow {
                val cs: CompletionStage<List<BitValue>> = channel.readCoils(
                    RequestParam(ubyte(1), Duration.ofSeconds(2)),
                    AddressRange(ushort(0), ushort(1))
                )
                val values: List<BitValue> = cs.toCompletableFuture().join()
                println(values.joinToString { "i=${it.index}, v=${it.value}" })

                val cs2: CompletionStage<Nothing> = channel.writeSingleCoil(
                    RequestParam(ubyte(1), Duration.ofSeconds(2)),
                    BitValue(ushort(0), true)
                )
                cs2.toCompletableFuture().join()
            }
        } finally {
            channel.disable()
            channel.shutdown()
        }
    }

    class ConsoleLogger : Logger {
        override fun onMessage(level: LogLevel?, message: String?) {
            print(message)
        }
    }

    class TestClientStateListener(
        private val queue: LinkedBlockingQueue<ClientState>
    ) : ClientStateListener {

        override fun onChange(state: ClientState) {
            println("client state: $state")
            queue.put(state)
        }
    }

    private fun awaitConnectedState(queue: LinkedBlockingQueue<ClientState>) {
        while (true) {
            val state = queue.take()
            if (state == ClientState.CONNECTED) {
                break
            }
            if (state == ClientState.WAIT_AFTER_FAILED_CONNECT) {
                throw Exception("failed to connect")
            }
        }
    }

}
