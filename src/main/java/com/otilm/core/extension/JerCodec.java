package com.otilm.core.extension;

import com.fasterxml.jackson.databind.JsonNode;
import com.otilm.api.exception.ValidationException;
import com.otilm.core.extension.ExtensionType.Choice;
import com.otilm.core.extension.ExtensionType.Member;
import com.otilm.core.extension.ExtensionType.Opaque;
import com.otilm.core.extension.ExtensionType.Range;
import com.otilm.core.extension.ExtensionType.Repeated;
import com.otilm.core.extension.ExtensionType.Scalar;
import com.otilm.core.extension.ExtensionType.Structure;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
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

    private JerCodec() {
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
            if (written == null || written.isNull() && member.optional()) {
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
        requireMemberCount(members.size(), type.presentMembers(), path);
        return type.set() ? new DERSet(members) : new DERSequence(members);
    }

    private static void requirePresent(Member member, String path) {
        if (!member.optional() && member.defaultValue() == null) {
            throw refusal(path + "." + member.name(), "is required");
        }
    }

    private static boolean isDefault(JsonNode written, Member member) {
        if (member.defaultValue() == null) {
            return false;
        }
        Object defaulted = member.defaultValue();
        if (defaulted instanceof Boolean flag) {
            return written.isBoolean() && written.booleanValue() == flag;
        }
        if (defaulted instanceof Number number && written.isIntegralNumber()) {
            return written.bigIntegerValue().equals(BigInteger.valueOf(number.longValue()));
        }
        return Objects.equals(defaulted.toString(), written.asText());
    }

    private static void rejectUndeclared(JsonNode value, List<Member> declared, String path) {
        for (Iterator<String> names = value.fieldNames(); names.hasNext();) {
            String written = names.next();
            if (declared.stream().noneMatch(member -> member.name().equals(written))) {
                throw refusal(path + "." + written, "is not a member of this extension");
            }
        }
    }

    private static void requireMemberCount(int present, Range required, String path) {
        if (required != null && !required.admits(BigInteger.valueOf(present))) {
            throw refusal(path, "carries %d members, which the extension does not permit".formatted(present));
        }
    }

    private static ASN1Encodable repeated(JsonNode value, Repeated type, String path) {
        if (!value.isArray()) {
            throw refusal(path, "must be an array");
        }
        requireSize(value.size(), type.size(), path, "elements");
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
            case INTEGER -> new ASN1Integer(integer(value, type.valueRange(), path));
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

    private static BigInteger integer(JsonNode value, Range range, String path) {
        if (!value.isIntegralNumber()) {
            throw refusal(path, "must be a whole number");
        }
        BigInteger written = value.bigIntegerValue();
        if (range != null && !range.admits(written)) {
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
        if (type.pattern() != null && !written.matches(type.pattern())) {
            throw refusal(path, "does not match the permitted form");
        }
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

    private static void requireSize(int actual, Object permitted, String path, String unit) {
        List<Range> ranges = permitted instanceof Range single ? List.of(single) : asRanges(permitted);
        if (ranges.isEmpty()) {
            return;
        }
        BigInteger size = BigInteger.valueOf(actual);
        if (ranges.stream().noneMatch(range -> range.admits(size))) {
            throw refusal(path, "carries %d %s, which the extension does not permit".formatted(actual, unit));
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Range> asRanges(Object permitted) {
        return permitted == null ? List.of() : (List<Range>) permitted;
    }

    private static ValidationException refusal(String path, String reason) {
        return new ValidationException("Extension value at %s %s".formatted(path, reason));
    }
}
