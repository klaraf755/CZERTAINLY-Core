package com.otilm.core.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.otilm.api.exception.ValidationException;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Translates an extension value written with member names into the ASN.1 JSON tree the codec encodes.
 *
 * <p>
 * The tree names each node's ASN.1 type because DER needs a type the value alone cannot supply, which costs the member
 * names the specification gives. A registered schema already carries the types and the tagging, and a {@code title}
 * carries the name, so together they are what a compiled ASN.1 module would be: enough to read {@code {"tier": 1}} and
 * know it encodes an INTEGER.
 *
 * <p>
 * The schema is therefore the whole of the translation. Where it does not determine a shape this refuses rather than
 * guesses, because a guess would encode something the author did not write.
 */
public final class NamedValueTranslator {

    private static final ObjectMapper MAPPER = ObjectMapperFactory.wire();
    private static final String TITLE = "title";
    private static final String PROPERTIES = "properties";
    private static final String REQUIRED = "required";
    private static final String ONE_OF = "oneOf";
    private static final String PREFIX_ITEMS = "prefixItems";
    private static final String ITEMS = "items";
    private static final String CONST = "const";

    private NamedValueTranslator() {
    }

    /**
     * A translated value and the named path each tree location came from, so a message about the tree can be reported
     * against what its author actually wrote.
     */
    public record Translated(JsonNode tree, Map<String, String> namedPaths) {
    }

    /**
     * Whether {@code value} is written with member names rather than as a tree. A tree node is an object with exactly
     * one key naming an ASN.1 type; registration refuses a {@code title} that collides with one, so no named value can
     * take that shape.
     */
    public static boolean isNamedForm(JsonNode value) {
        if (value == null || !value.isObject()) {
            return false;
        }
        return value.size() != 1 || !AsnJsonCodec.NODE_TYPES.contains(value.fieldNames().next());
    }

    public static Translated translate(JsonNode named, JsonNode schema) {
        Map<String, String> paths = new LinkedHashMap<>();
        JsonNode tree = node(named, schema, "$", "$", paths);
        return new Translated(tree, paths);
    }

    /**
     * The named path a tree location came from: the longest recorded prefix, plus whatever the message added beyond it.
     * A violation reported at {@code $.sequence[1].integer} belongs to the member recorded at {@code $.sequence[1]}.
     */
    public static String namedPath(Map<String, String> namedPaths, String treePath) {
        String bestTree = "";
        String bestNamed = null;
        for (Map.Entry<String, String> entry : namedPaths.entrySet()) {
            if (treePath.startsWith(entry.getKey()) && entry.getKey().length() > bestTree.length()) {
                bestTree = entry.getKey();
                bestNamed = entry.getValue();
            }
        }
        return bestNamed == null ? treePath : bestNamed;
    }

    private static JsonNode node(JsonNode named, JsonNode schema, String treePath, String namedPath,
            Map<String, String> paths) {
        paths.put(treePath, namedPath);
        if (schema == null || !schema.isObject()) {
            throw refusal(namedPath, "the schema does not describe it");
        }
        if (schema.has(ONE_OF)) {
            return choice(named, schema.get(ONE_OF), treePath, namedPath, paths);
        }
        String type = nodeType(schema, namedPath);
        return switch (type) {
            case "sequence", "set" -> collection(named, schema, type, treePath, namedPath, paths);
            case "tagged" -> tagged(named, schema, treePath, namedPath, paths);
            default -> MAPPER.createObjectNode().set(type, leaf(named, type, namedPath));
        };
    }

    /** The ASN.1 type a subschema pins, which is the single entry of its {@code required}. */
    private static String nodeType(JsonNode schema, String namedPath) {
        JsonNode required = schema.get(REQUIRED);
        if (required == null || !required.isArray() || required.size() != 1) {
            throw refusal(namedPath, "the schema does not name exactly one ASN.1 type for it");
        }
        String type = required.get(0).asText();
        if (!AsnJsonCodec.NODE_TYPES.contains(type)) {
            throw refusal(namedPath, "the schema requires '%s', which is not an ASN.1 node type".formatted(type));
        }
        return type;
    }

    /** A CHOICE: the author names the alternative, and its title is what selects the branch. */
    private static JsonNode choice(JsonNode named, JsonNode branches, String treePath, String namedPath,
            Map<String, String> paths) {
        if (named == null || !named.isObject() || named.size() != 1) {
            throw refusal(namedPath, "it must name exactly one alternative");
        }
        Map.Entry<String, JsonNode> chosen = named.properties().iterator().next();
        for (JsonNode branch : branches) {
            if (branch.isObject() && chosen.getKey().equals(title(branch))) {
                return node(chosen.getValue(), branch, treePath, namedPath + "." + chosen.getKey(), paths);
            }
        }
        throw refusal(namedPath + "." + chosen.getKey(), "no alternative of that name exists");
    }

    private static JsonNode collection(JsonNode named, JsonNode schema, String type, String treePath, String namedPath,
            Map<String, String> paths) {
        JsonNode inner = schema.path(PROPERTIES).path(type);
        ArrayNode members = MAPPER.createArrayNode();
        if (inner.has(PREFIX_ITEMS)) {
            record(named, inner.get(PREFIX_ITEMS), members, type, treePath, namedPath, paths);
        } else if (inner.has(ITEMS) && inner.get(ITEMS).isObject()) {
            list(named, inner.get(ITEMS), members, type, treePath, namedPath, paths);
        } else {
            throw refusal(namedPath, "the schema describes neither its members nor its element type");
        }
        return MAPPER.createObjectNode().set(type, members);
    }

    /** A SEQUENCE of declared members: each present name contributes, in the order the schema declares. */
    private static void record(JsonNode named, JsonNode prefixItems, ArrayNode members, String type, String treePath,
            String namedPath, Map<String, String> paths) {
        if (named == null || !named.isObject()) {
            throw refusal(namedPath, "it must be an object naming the members");
        }
        List<String> declared = new ArrayList<>();
        for (JsonNode member : prefixItems) {
            String name = title(member);
            if (name == null) {
                throw refusal(namedPath, "the schema leaves one of its members unnamed");
            }
            declared.add(name);
            if (named.has(name)) {
                String childTree = "%s.%s[%d]".formatted(treePath, type, members.size());
                members.add(node(named.get(name), member, childTree, namedPath + "." + name, paths));
            }
        }
        for (String written : (Iterable<String>) named::fieldNames) {
            if (!declared.contains(written)) {
                throw refusal(namedPath + "." + written, "the extension has no member of that name");
            }
        }
    }

    /** A SEQUENCE OF / SET OF: every element takes the same schema, so the author writes a JSON array. */
    private static void list(JsonNode named, JsonNode items, ArrayNode members, String type, String treePath,
            String namedPath, Map<String, String> paths) {
        if (named == null || !named.isArray()) {
            throw refusal(namedPath, "it must be an array");
        }
        int index = 0;
        for (JsonNode element : named) {
            String childTree = "%s.%s[%d]".formatted(treePath, type, index);
            members.add(node(element, items, childTree, "%s[%d]".formatted(namedPath, index), paths));
            index++;
        }
    }

    /**
     * A tagged member is transparent to the author: the tag belongs to the extension's definition, not to the value, so
     * the schema must pin both parts of it.
     */
    private static JsonNode tagged(JsonNode named, JsonNode schema, String treePath, String namedPath,
            Map<String, String> paths) {
        JsonNode tag = schema.path(PROPERTIES).path("tagged").path(PROPERTIES);
        JsonNode tagNo = tag.path("tagNo").get(CONST);
        JsonNode explicit = tag.path("explicit").get(CONST);
        if (tagNo == null || !tagNo.isIntegralNumber() || explicit == null || !explicit.isBoolean()) {
            throw refusal(namedPath, "the schema does not pin its tag number and tagging mode");
        }
        ObjectNode tagged = MAPPER.createObjectNode();
        tagged.set("tagNo", tagNo);
        tagged.set("explicit", explicit);
        tagged.set("value", node(named, tag.path("value"), treePath + ".tagged.value", namedPath, paths));
        return MAPPER.createObjectNode().set("tagged", tagged);
    }

    /**
     * A leaf value passes through unchanged: the codec is the authority on what each type accepts, so checking it here
     * would be a second, divergent grammar. {@code bitString} is an object of its own members rather than a scalar, and
     * is written the same way in both forms.
     */
    private static JsonNode leaf(JsonNode named, String type, String namedPath) {
        if (named == null || named.isMissingNode()) {
            throw refusal(namedPath, "no value was written");
        }
        return named;
    }

    private static String title(JsonNode schema) {
        JsonNode title = schema == null ? null : schema.get(TITLE);
        return title != null && title.isTextual() ? title.textValue() : null;
    }

    private static ValidationException refusal(String namedPath, String reason) {
        return new ValidationException("Extension value at %s cannot be translated: %s".formatted(namedPath, reason));
    }
}
