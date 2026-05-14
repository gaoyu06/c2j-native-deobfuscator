package j2c.common

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import java.nio.file.Files
import java.nio.file.Path

object JsonIO {
    val mapper = jacksonObjectMapper()
        .enable(SerializationFeature.INDENT_OUTPUT)
        .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)

    inline fun <reified T> read(path: Path): T =
        Files.newInputStream(path).use { mapper.readValue(it) }

    fun write(path: Path, value: Any) {
        Files.createDirectories(path.toAbsolutePath().parent)
        Files.newOutputStream(path).use { mapper.writeValue(it, value) }
    }

    fun toJson(value: Any): String = mapper.writeValueAsString(value)
}
