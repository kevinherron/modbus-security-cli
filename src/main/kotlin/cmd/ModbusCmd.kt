package cmd

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option

class ModbusCmd : CliktCommand("modbus") {

    private val debug: Boolean by option(
        "--debug",
        help = "Enable debug logging"
    ).flag()

    override fun run() {
        if (debug) {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug")
        }
    }

}
