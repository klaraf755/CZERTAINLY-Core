package com.otilm.core.extension;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.otilm.api.exception.ValidationException;
import com.otilm.core.extension.ExtensionType.Choice;
import com.otilm.core.extension.ExtensionType.Member;
import com.otilm.core.extension.ExtensionType.Opaque;
import com.otilm.core.extension.ExtensionType.Repeated;
import com.otilm.core.extension.ExtensionType.Scalar;
import com.otilm.core.extension.ExtensionType.Structure;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.io.IOException;
import java.util.HexFormat;
import java.util.List;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;

/**
 * Reads an extension's DER back into the JSON form its author would have written, guided by the same
 * {@link ExtensionType} that encodes it.
 *
 * <p>
 * Without a type this direction is not a function: {@code A0 03 02 01 01} is both an implicitly tagged SEQUENCE of one
 * INTEGER and an explicitly tagged INTEGER, and the bytes record no preference. A registered module settles it, which
 * is what makes an extension on a stored certificate - or on an uploaded request - readable at all.
 *
 * <p>
 * A DEFAULT that was omitted comes back as its default value, because a reader wants the extension's effective content
 * rather than a transcript of which octets were present.
 */
public final class JerDecoder {

    private static final ObjectMapper MAPPER = ObjectMapperFactory.wire();

    private JerDecoder() {
    }

    public static JsonNode decode(byte[] der, ExtensionType type) {
        ASN1Primitive parsed;
        try {
            parsed = ASN1Primitive.fromByteArray(der);
        } catch (IOException | IllegalArgumentException e) {
            throw new ValidationException("Extension value is not valid DER");
        }
        return value(parsed, type, "$");
    }

    private static JsonNode value(ASN1Encodable encoded, ExtensionType type, String path) {
        return switch (type) {
            case Scalar scalar -> scalar(encoded, scalar, path);
            case Structure structure -> structure(encoded, structure, path);
            case Repeated repeated -> repeated(encoded, repeated, path);
            case Choice choice -> choice(encoded, choice, path);
            case Opaque ignored -> hexOf(encoded, path);
        };
    }

    private static JsonNode structure(ASN1Encodable encoded, Structure type, String path) {
        List<ASN1Encodable> components = componentsOf(encoded, type.set(), path);
        ObjectNode out = MAPPER.createObjectNode();
        int next = 0;
        for (Member member : type.members()) {
            ASN1Encodable component = next < components.size() ? components.get(next) : null;
            if (component != null && fits(component, member)) {
                out
                        .set(member.name(),
                                value(untag(component, member, path), member.type(), path + "." + member.name()));
                next++;
            } else if (member.defaultValue() != null) {
                out.set(member.name(), MAPPER.valueToTree(member.defaultValue()));
            } else if (!member.optional()) {
                throw new ValidationException("Extension value at %s.%s is missing".formatted(path, member.name()));
            }
        }
        if (next < components.size()) {
            throw new ValidationException(
                    "Extension value at %s carries more members than the extension declares".formatted(path));
        }
        return out;
    }

    /**
     * Whether a component is the member the type expects next. An optional member the value omitted leaves the next
     * member's component in its place, so this is what keeps the two lists aligned - the tag decides where there is
     * one, and the universal tag where there is not.
     */
    private static boolean fits(ASN1Encodable component, Member member) {
        ASN1Primitive primitive = component.toASN1Primitive();
        if (member.tag() != null) {
            return primitive instanceof ASN1TaggedObject tagged && tagged.getTagNo() == member.tag();
        }
        return matchesType(primitive, member.type());
    }

    private static boolean matchesType(ASN1Primitive primitive, ExtensionType type) {
        return switch (type) {
            case Opaque ignored -> true;
            case Choice choice -> choice.alternatives().stream().anyMatch(alt -> fits(primitive, alt));
            case Structure structure ->
                structure.set() ? primitive instanceof ASN1Set : primitive instanceof ASN1Sequence;
            case Repeated repeated -> repeated.set() ? primitive instanceof ASN1Set : primitive instanceof ASN1Sequence;
            case Scalar scalar -> matchesScalar(primitive, scalar);
        };
    }

    private static boolean matchesScalar(ASN1Primitive primitive, Scalar scalar) {
        return switch (scalar.primitive()) {
            case BOOLEAN -> primitive instanceof ASN1Boolean;
            case INTEGER -> primitive instanceof ASN1Integer;
            case OID -> primitive instanceof ASN1ObjectIdentifier;
            case OCTET_STRING -> primitive instanceof ASN1OctetString;
            case BIT_STRING -> primitive instanceof ASN1BitString;
            case GENERALIZED_TIME -> primitive instanceof ASN1GeneralizedTime;
            case NULL -> primitive instanceof ASN1Null;
            case UTF8_STRING, IA5_STRING, PRINTABLE_STRING -> primitive instanceof ASN1String;
        };
    }

    /** Strips a member's context tag, which is the one place the implicit/explicit distinction is resolved. */
    private static ASN1Encodable untag(ASN1Encodable component, Member member, String path) {
        if (member.tag() == null) {
            return component;
        }
        ASN1TaggedObject tagged = (ASN1TaggedObject) component.toASN1Primitive();
        try {
            return member.explicit()
                    ? tagged.getExplicitBaseObject()
                    : tagged.getBaseUniversal(false, universalTag(member.type()));
        } catch (RuntimeException e) {
            throw new ValidationException(
                    "Extension value at %s.%s is not the shape its tag declares".formatted(path, member.name()));
        }
    }

    private static int universalTag(ExtensionType type) {
        return switch (type) {
            case Structure structure -> structure.set() ? BERTags.SET : BERTags.SEQUENCE;
            case Repeated repeated -> repeated.set() ? BERTags.SET : BERTags.SEQUENCE;
            // A CHOICE cannot be implicitly tagged, and an undescribed member has no universal tag to ask for.
            case Choice ignored -> throw new IllegalStateException("a choice is never implicitly tagged");
            case Opaque ignored -> BERTags.OCTET_STRING;
            case Scalar scalar -> switch (scalar.primitive()) {
                case BOOLEAN -> BERTags.BOOLEAN;
                case INTEGER -> BERTags.INTEGER;
                case OID -> BERTags.OBJECT_IDENTIFIER;
                case UTF8_STRING -> BERTags.UTF8_STRING;
                case IA5_STRING -> BERTags.IA5_STRING;
                case PRINTABLE_STRING -> BERTags.PRINTABLE_STRING;
                case OCTET_STRING -> BERTags.OCTET_STRING;
                case BIT_STRING -> BERTags.BIT_STRING;
                case GENERALIZED_TIME -> BERTags.GENERALIZED_TIME;
                case NULL -> BERTags.NULL;
            };
        };
    }

    private static JsonNode repeated(ASN1Encodable encoded, Repeated type, String path) {
        List<ASN1Encodable> elements = componentsOf(encoded, type.set(), path);
        ArrayNode out = MAPPER.createArrayNode();
        int index = 0;
        for (ASN1Encodable element : elements) {
            out.add(value(element, type.element(), "%s[%d]".formatted(path, index++)));
        }
        return out;
    }

    private static JsonNode choice(ASN1Encodable encoded, Choice type, String path) {
        for (Member alternative : type.alternatives()) {
            if (fits(encoded, alternative)) {
                ObjectNode out = MAPPER.createObjectNode();
                out
                        .set(alternative.name(), value(untag(encoded, alternative, path), alternative.type(),
                                path + "." + alternative.name()));
                return out;
            }
        }
        throw new ValidationException("Extension value at %s matches no alternative of this choice".formatted(path));
    }

    private static JsonNode scalar(ASN1Encodable encoded, Scalar type, String path) {
        ASN1Primitive primitive = encoded.toASN1Primitive();
        if (!matchesScalar(primitive, type)) {
            throw new ValidationException(
                    "Extension value at %s is not the ASN.1 type the extension declares".formatted(path));
        }
        return switch (type.primitive()) {
            case BOOLEAN -> MAPPER.getNodeFactory().booleanNode(((ASN1Boolean) primitive).isTrue());
            case INTEGER -> MAPPER.getNodeFactory().numberNode(((ASN1Integer) primitive).getValue());
            case OID -> MAPPER.getNodeFactory().textNode(primitive.toString());
            case NULL -> MAPPER.nullNode();
            case GENERALIZED_TIME ->
                MAPPER.getNodeFactory().textNode(((ASN1GeneralizedTime) primitive).getTimeString());
            case OCTET_STRING -> MAPPER
                    .getNodeFactory()
                    .textNode(HexFormat.of().formatHex(((ASN1OctetString) primitive).getOctets()).toUpperCase());
            case BIT_STRING -> bitString((ASN1BitString) primitive);
            case UTF8_STRING, IA5_STRING, PRINTABLE_STRING ->
                MAPPER.getNodeFactory().textNode(((ASN1String) primitive).getString());
        };
    }

    private static JsonNode bitString(ASN1BitString bits) {
        byte[] octets = bits.getBytes();
        ObjectNode out = MAPPER.createObjectNode();
        out.put("value", HexFormat.of().formatHex(octets).toUpperCase());
        out.put("length", octets.length * 8 - bits.getPadBits());
        return out;
    }

    private static JsonNode hexOf(ASN1Encodable encoded, String path) {
        try {
            return MAPPER
                    .getNodeFactory()
                    .textNode(HexFormat
                            .of()
                            .formatHex(encoded.toASN1Primitive().getEncoded(ASN1Encoding.DER))
                            .toUpperCase());
        } catch (IOException e) {
            throw new ValidationException("Extension value at %s could not be read".formatted(path));
        }
    }

    private static List<ASN1Encodable> componentsOf(ASN1Encodable encoded, boolean set, String path) {
        ASN1Primitive primitive = encoded.toASN1Primitive();
        if (set && primitive instanceof ASN1Set asn1Set) {
            return List.of(asn1Set.toArray());
        }
        if (!set && primitive instanceof ASN1Sequence sequence) {
            return List.of(sequence.toArray());
        }
        throw new ValidationException(
                "Extension value at %s is not the %s the extension declares".formatted(path, set ? "SET" : "SEQUENCE"));
    }
}
