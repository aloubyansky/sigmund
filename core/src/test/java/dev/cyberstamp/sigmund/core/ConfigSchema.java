package dev.cyberstamp.sigmund.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.Error;
import com.networknt.schema.InputFormat;
import com.networknt.schema.Schema;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SpecificationVersion;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.List;

/**
 * The published {@code sigmund.yaml} schema, loaded from the classpath for tests.
 *
 * <p>
 * Sigmund never consults the schema at runtime, so it is validated only here, with a validator
 * that is a test dependency. The validator parses documents itself, with its own Jackson; the
 * vocabularies the schema lists are read as plain JSON with Sigmund's.
 */
final class ConfigSchema {

    /** The schema as plain JSON, for reading the vocabularies it lists. */
    static final JsonNode JSON = readJson();

    private static final Schema SCHEMA = loadSchema();

    private ConfigSchema() {
    }

    /**
     * Validates a {@code sigmund.yaml} document.
     *
     * @param yaml the document; an empty one is an empty mapping, as Sigmund reads it
     * @return the schema's error messages, empty when the document is valid
     */
    static List<String> errors(String yaml) {
        List<Error> errors = yaml.isBlank()
                ? SCHEMA.validate("{}", InputFormat.JSON)
                : SCHEMA.validate(yaml, InputFormat.YAML);
        return errors.stream().map(Error::toString).sorted().toList();
    }

    private static JsonNode readJson() {
        try (InputStream in = resource()) {
            return new ObjectMapper().readTree(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Schema loadSchema() {
        try (InputStream in = resource()) {
            return SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12).getSchema(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static InputStream resource() {
        InputStream in = ConfigSchema.class.getResourceAsStream("/" + SigmundSchema.RESOURCE);
        if (in == null) {
            throw new IllegalStateException(SigmundSchema.RESOURCE + " is not on the classpath");
        }
        return in;
    }
}
