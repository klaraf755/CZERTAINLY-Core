package com.otilm.core.extension;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.otilm.api.exception.ValidationException;
import com.otilm.core.extension.ExtensionType.Choice;
import com.otilm.core.extension.ExtensionType.ComponentRule;
import com.otilm.core.extension.ExtensionType.Member;
import com.otilm.core.extension.ExtensionType.Opaque;
import com.otilm.core.extension.ExtensionType.Range;
import com.otilm.core.extension.ExtensionType.Repeated;
import com.otilm.core.extension.ExtensionType.Scalar;
import com.otilm.core.extension.ExtensionType.Structure;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Encodes a JSON value of a known {@link ExtensionType} into DER, in the JSON Encoding Rules of ITU-T X.697.
 *
 * <p>
 * The type supplies everything the JSON cannot: which ASN.1 type each member has, what tag it carries and whether that
 * tag wraps or replaces. A value therefore names its members and nothing else - the same text encodes differently under
 * a different type, which is exactly why one must be registered before a value can be written at all.
 *
 * <p>
 * The type is also the only authority consulted. Where it does not determine something this refuses rather than
 * choosing, because a choice made here would encode something its author did not write.
 */
public final class JerCodec {

    private static final Logger logger = LoggerFactory.getLogger(JerCodec.class);
    private static final String VALUE = "value";
    private static final String LENGTH = "length";

    /**
     * Trailing text and duplicate keys are both silent losses otherwise: text after the first complete value is
     * discarded, and a repeated key collapses to the last, so a value would encode something other than what was
     * written.
     */
    private static final ObjectReader STRICT_READER = ((ObjectMapper) ObjectMapperFactory.wire())
            .reader()
            .with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .with(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);

    private JerCodec() {
    }

    /** Parses a value's text. One place reads it, so a caller cannot judge a different value than it encodes. */
    public static JsonNode parse(String json) {
        try {
            JsonNode value = STRICT_READER.readTree(json);
            if (value == null) {
                throw new ValidationException("Extension value is not well-formed JSON");
            }
            return value;
        } catch (java.io.IOException e) {
            throw new ValidationException("Extension value is not well-formed JSON");
        }
    }

    public static byte[] encodeFromString(String json, ExtensionType type) {
        return encode(parse(json), type);
    }

    /**
     * The value as JSON when it was written out, or empty when it was handed over as base64 DER. The two are told apart
     * by parsing, not by peeking at a character: a base64 string is a run of letters, digits, {@code +}, {@code /} and
     * {@code =}, and no such run of more than a few characters is a complete JSON value - a leading digit is followed
     * by letters the JSON grammar has no place for. The one overlap, a string of digits only, decodes to bytes whose
     * second byte would have to be a DER length longer than the blob itself.
     */
    public static Optional<JsonNode> tryParse(String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.ofNullable(STRICT_READER.readTree(value));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    /** Whether a value was written out in JSON rather than handed over as base64 DER. */
    public static boolean looksWritten(String value) {
        return tryParse(value).isPresent();
    }

    public static byte[] encode(JsonNode value, ExtensionType type) {
        try {
            return encodable(value, type, "$").toASN1Primitive().getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new ValidationException("Extension value could not be encoded to DER");
        } catch (ValidationException e) {
            throw e;
        } catch (RuntimeException e) {
            // BouncyCastle rejects some values with its own unchecked exceptions, whose messages name library
            // internals and would otherwise reach a request client as a 500. Logged because arriving here means
            // either a shape this should have named or a defect.
            logger.warn("Encoding an extension value failed outside this codec's own checks", e);
            throw new ValidationException("Extension value could not be encoded to DER");
        }
    }

    private static ASN1Encodable encodable(JsonNode value, ExtensionType type, String path) {
        return switch (type) {
            case Scalar scalar -> scalar(value, scalar, path);
            case Structure structure -> structure(value, structure, path);
            case Repeated repeated -> repeated(value, repeated, path);
            case Choice choice -> choice(value, choice, path);
            case Opaque opaque -> opaque(value, opaque, path);
        };
    }

    /** A member's tag is applied here rather than by the member's own type, which knows nothing about it. */
    private static ASN1Encodable tagged(ASN1Encodable encoded, Member member) {
        return member.tag() == null ? encoded : new DERTaggedObject(member.explicit(), member.tag(), encoded);
    }

    private static ASN1Encodable structure(JsonNode value, Structure type, String path) {
        if (!value.isObject()) {
            throw refusal(path, "must be an object naming the members");
        }
        // Before anything else: an unwritten member is usually one that was misspelt, and naming the
        // spelling points at the mistake where "the member it should have been is required" would not.
        rejectUndeclared(value, type.members(), path);
        ASN1EncodableVector members = new ASN1EncodableVector();
        for (Member member : type.members()) {
            JsonNode written = value.get(member.name());
            if (written == null) {
                // Absent means absent. A written null is not: it is the JER value of ASN.1 NULL, and for any
                // other type it is a wrong value the type's own check names.
                requirePresent(member, path);
                continue;
            }
            if (isDefault(written, member)) {
                // DER forbids encoding a DEFAULT value, so writing one means leaving the member out. Accepting
                // it and omitting it is kinder than refusing: the author said what they meant.
                continue;
            }
            members.add(tagged(encodable(written, member.type(), path + "." + member.name()), member));
        }
        requireComponentAlternatives(value, type, path);
        return type.set() ? new DERSet(members) : new DERSequence(members);
    }

    /**
     * A value must satisfy at least one alternative of the type's {@code WITH COMPONENTS} constraint. A member written
     * as its DEFAULT counts as absent for PRESENT and ABSENT, since that is what it encodes to, but as holding that
     * value for an EQUALS rule, since that is what it means.
     */
    private static void requireComponentAlternatives(JsonNode value, Structure type, String path) {
        if (type.componentAlternatives().isEmpty()) {
            return;
        }
        for (List<ComponentRule> alternative : type.componentAlternatives()) {
            if (alternative.stream().allMatch(rule -> holds(rule, value, type))) {
                return;
            }
        }
        throw refusal(path, "must " + type
                .componentAlternatives()
                .stream()
                .map(alternative -> alternative.stream().map(JerCodec::describe).collect(Collectors.joining(" and ")))
                .collect(Collectors.joining(", or ")));
    }

    private static boolean holds(ComponentRule rule, JsonNode value, Structure type) {
        Member member = type.members().stream().filter(m -> m.name().equals(rule.member())).findFirst().orElse(null);
        JsonNode written = value.get(rule.member());
        boolean present = written != null && !(member != null && isDefault(written, member));
        return switch (rule.presence()) {
            case PRESENT -> present;
            case ABSENT -> !present;
            case EQUALS -> written != null
                    ? literalEquals(written, rule.value())
                    : member != null && member.defaultValue() != null
                            && Objects.equals(normalise(member.defaultValue()), normalise(rule.value()));
        };
    }

    private static String describe(ComponentRule rule) {
        return switch (rule.presence()) {
            case PRESENT -> "have " + rule.member();
            case ABSENT -> "omit " + rule.member();
            case EQUALS -> "have " + rule.member() + " = " + rule.value();
        };
    }

    private static void requirePresent(Member member, String path) {
        if (!member.optional() && member.defaultValue() == null) {
            throw refusal(path + "." + member.name(), "is required");
        }
    }

    private static boolean isDefault(JsonNode written, Member member) {
        return member.defaultValue() != null && literalEquals(written, member.defaultValue());
    }

    /** Whether a written JSON value is the ASN.1 literal a module wrote: TRUE, FALSE, a number, or a bare word. */
    private static boolean literalEquals(JsonNode written, Object literal) {
        if (literal instanceof Boolean flag) {
            return written.isBoolean() && written.booleanValue() == flag;
        }
        if (literal instanceof Number number && written.isIntegralNumber()) {
            return written.bigIntegerValue().equals(normalise(number));
        }
        return Objects.equals(literal.toString(), written.asText());
    }

    private static Object normalise(Object literal) {
        return literal instanceof Number number && !(number instanceof BigInteger)
                ? BigInteger.valueOf(number.longValue())
                : literal;
    }

    private static void rejectUndeclared(JsonNode value, List<Member> declared, String path) {
        for (Iterator<String> names = value.fieldNames(); names.hasNext();) {
            String written = names.next();
            if (declared.stream().noneMatch(member -> member.name().equals(written))) {
                throw refusal(path + "." + written, "is not a member of this extension");
            }
        }
    }

    private static ASN1Encodable repeated(JsonNode value, Repeated type, String path) {
        if (!value.isArray()) {
            throw refusal(path, "must be an array");
        }
        requireSize(value.size(), type.sizes(), path, "elements");
        ASN1EncodableVector elements = new ASN1EncodableVector();
        int index = 0;
        for (JsonNode element : value) {
            elements.add(encodable(element, type.element(), "%s[%d]".formatted(path, index++)));
        }
        return type.set() ? new DERSet(elements) : new DERSequence(elements);
    }

    /** A CHOICE value names its alternative, which is the only thing that can select one. */
    private static ASN1Encodable choice(JsonNode value, Choice type, String path) {
        if (!value.isObject() || value.size() != 1) {
            throw refusal(path, "must name exactly one alternative");
        }
        String name = value.fieldNames().next();
        for (Member alternative : type.alternatives()) {
            if (alternative.name().equals(name)) {
                String alternativePath = path + "." + name;
                return tagged(encodable(value.get(name), alternative.type(), alternativePath), alternative);
            }
        }
        throw refusal(path + "." + name, "is not an alternative of this choice");
    }

    private static ASN1Encodable opaque(JsonNode value, Opaque type, String path) {
        byte[] der = hex(value, path);
        try {
            return ASN1Primitive.fromByteArray(der);
        } catch (IOException e) {
            throw refusal(path, "is not valid DER, which is the only form %s can take here".formatted(type.asn1Name()));
        }
    }

    private static ASN1Encodable scalar(JsonNode value, Scalar type, String path) {
        return switch (type.primitive()) {
            case BOOLEAN -> ASN1Boolean.getInstance(bool(value, path));
            case INTEGER -> new ASN1Integer(integer(value, type.valueRanges(), path));
            case OID -> new ASN1ObjectIdentifier(text(value, type, path));
            case UTF8_STRING -> new DERUTF8String(text(value, type, path));
            case IA5_STRING -> new DERIA5String(text(value, type, path), true);
            case PRINTABLE_STRING -> new DERPrintableString(text(value, type, path), true);
            case GENERALIZED_TIME -> new DERGeneralizedTime(text(value, type, path));
            case OCTET_STRING -> octetString(value, type, path);
            case BIT_STRING -> bitString(value, type, path);
            case NULL -> derNull(value, path);
        };
    }

    private static ASN1Encodable octetString(JsonNode value, Scalar type, String path) {
        byte[] octets = hex(value, path);
        requireSize(octets.length, type.sizes(), path, "octets");
        return new DEROctetString(octets);
    }

    /** X.697 gives a variable-length bit string as a value and a count of the bits that matter. */
    private static ASN1Encodable bitString(JsonNode value, Scalar type, String path) {
        if (!value.isObject() || !value.has(VALUE)) {
            throw refusal(path, "must carry a hexadecimal value and a length in bits");
        }
        byte[] octets = hex(value.get(VALUE), path + "." + VALUE);
        int bits = value.has(LENGTH) ? value.get(LENGTH).asInt(-1) : octets.length * 8;
        if (bits < 0 || bits > octets.length * 8 || bits <= (octets.length - 1) * 8) {
            throw refusal(path + "." + LENGTH, "does not match the %d octets written".formatted(octets.length));
        }
        requireSize(bits, type.sizes(), path, "bits");
        return new DERBitString(octets, octets.length * 8 - bits);
    }

    private static ASN1Encodable derNull(JsonNode value, String path) {
        if (!value.isNull()) {
            throw refusal(path, "must be null; ASN.1 NULL carries no value");
        }
        return DERNull.INSTANCE;
    }

    private static boolean bool(JsonNode value, String path) {
        if (!value.isBoolean()) {
            throw refusal(path, "must be true or false");
        }
        return value.booleanValue();
    }

    private static BigInteger integer(JsonNode value, List<Range> ranges, String path) {
        if (!value.isIntegralNumber()) {
            throw refusal(path, "must be a whole number");
        }
        BigInteger written = value.bigIntegerValue();
        if (!ranges.isEmpty() && ranges.stream().noneMatch(range -> range.admits(written))) {
            throw refusal(path, "is outside the permitted range");
        }
        return written;
    }

    private static String text(JsonNode value, Scalar type, String path) {
        if (!value.isTextual()) {
            throw refusal(path, "must be a string");
        }
        String written = value.textValue();
        requireSize(written.length(), type.sizes(), path, "characters");
        return written;
    }

    private static byte[] hex(JsonNode value, String path) {
        if (!value.isTextual()) {
            throw refusal(path, "must be a string of hexadecimal digits");
        }
        try {
            return HexFormat.of().parseHex(value.textValue());
        } catch (IllegalArgumentException e) {
            throw refusal(path, "is not an even-length string of hexadecimal digits");
        }
    }

    private static void requireSize(int actual, List<Range> permitted, String path, String unit) {
        if (!Range.anyAdmits(permitted, actual)) {
            throw refusal(path, "carries %d %s, which the extension does not permit".formatted(actual, unit));
        }
    }

    private static ValidationException refusal(String path, String reason) {
        return new ValidationException("Extension value at %s %s".formatted(path, reason));
    }
}
