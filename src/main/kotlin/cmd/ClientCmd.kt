package cmd

import com.digitalpetri.modbus.client.ModbusTcpClient
import com.digitalpetri.modbus.pdu.ReadHoldingRegistersRequest
import com.digitalpetri.modbus.pdu.ReadHoldingRegistersResponse
import com.digitalpetri.modbus.pdu.WriteSingleRegisterRequest
import com.digitalpetri.modbus.pdu.WriteSingleRegisterResponse
import com.digitalpetri.modbus.tcp.client.NettyTcpClientTransport
import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.int
import util.toKeyManagerFactory
import util.toTrustManagerFactory
import java.nio.file.Path
import java.security.KeyStore
import kotlin.io.path.inputStream


class Client : CliktCommand() {

    private val caKeyStore: String by option(
        "--ca-key-store",
        help = "The path to the CA KeyStore"
    ).default("./pki/ca.pfx")

    private val clientKeyStore: String by option(
        "--client-key-store",
        help = "The path to the Client KeyStore"
    ).default("./pki/client1.pfx")

    private val port: Int by option(
        "-p", "--port",
        help = "The port to connect to"
    ).int().default(802)

    private val unitId: Int by option(
        "-u", "--unit-id",
        help = "The unit ID to use"
    ).int().default(1)

    private val host: String by argument(name = "host", help = "The host to connect to")

    lateinit var client: ModbusTcpClient

    override fun help(context: Context): String = "Start a Modbus Security client"

    override fun run() {
        val transport = NettyTcpClientTransport.create { cfg ->
            cfg.hostname = host
            cfg.port = port
            cfg.connectPersistent = false

            cfg.tlsEnabled = true

            Path.of(clientKeyStore).let {
                val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                    load(it.inputStream(), CharArray(0))
                }
                cfg.keyManagerFactory = keyStore.toKeyManagerFactory()
            }

            Path.of(caKeyStore).let {
                val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                    load(it.inputStream(), CharArray(0))
                }
                cfg.trustManagerFactory = keyStore.toTrustManagerFactory()
            }
        }

        client = ModbusTcpClient.create(transport)
    }

    class Rhr : CliktCommand() {

        private val address: Int by argument(
            name = "address",
            help = "The address to read from"
        ).int()

        private val quantity: Int by argument(
            name = "quantity",
            help = "The quantity to read"
        ).int()

        override fun help(context: Context): String = "Read Holding Registers"

        override fun run() {
            val clientCmd: Client = currentContext.parent?.command as Client
            val client: ModbusTcpClient = clientCmd.client

            try {
                client.connect()
                echo("Connected to ${clientCmd.host}:${clientCmd.port}")

                val request = ReadHoldingRegistersRequest(address, quantity)
                echo("-> $request")

                val response: ReadHoldingRegistersResponse = client.readHoldingRegisters(
                    clientCmd.unitId,
                    request
                )
                echo("<- $response")
            } catch (e: Exception) {
                echo("${e.message}", err = true)
            } finally {
                if (client.isConnected) {
                    client.disconnect()
                    echo("Disconnected")
                }
            }
        }

    }

    class Wsr : CliktCommand() {

        private val address: Int by argument(
            name = "address",
            help = "The address to write to"
        ).int()

        private val value: Int by argument(name = "value", help = "The value to write").int()

        override fun help(context: Context): String = "Write Single Register"

        override fun run() {
            val clientCmd: Client = currentContext.parent?.command as Client
            val client: ModbusTcpClient = clientCmd.client

            try {
                client.connect()
                echo("Connected to ${clientCmd.host}:${clientCmd.port}")

                val request = WriteSingleRegisterRequest(address, value)
                echo("-> $request")

                val response: WriteSingleRegisterResponse = client.writeSingleRegister(
                    clientCmd.unitId,
                    request
                )
                echo("<- $response")
            } catch (e: Exception) {
                echo("${e.message}", err = true)
            } finally {
                if (client.isConnected) {
                    client.disconnect()
                    echo("Disconnected")
                }
            }
        }

    }

}
