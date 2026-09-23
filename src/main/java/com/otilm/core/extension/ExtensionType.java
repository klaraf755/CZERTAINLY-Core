package com.otilm.core.extension;

import java.math.BigInteger;
import java.util.List;

/**
 * The ASN.1 type of a certificate extension's value, as much of it as the platform needs to encode a value and check
 * it.
 *
 * <p>
 * This is the resolved form: type references are already inlined, so nothing here refers outward. It is an internal
 * model rather than a wire format - what an operator registers is the extension's ASN.1 module, and how that text
 * becomes this is the reader's business, not this model's.
 */
public sealed interface ExtensionType {

    /** The ASN.1 types whose values the platform can build from JSON. */
    enum Primitive {
        BOOLEAN,
        INTEGER,
        OID,
        UTF8_STRING,
        IA5_STRING,
        PRINTABLE_STRING,
        OCTET_STRING,
        BIT_STRING,
        GENERALIZED_TIME,
        NULL
    }

    /**
     * A member of a SEQUENCE, or an alternative of a CHOICE.
     *
     * @param tag the context tag number, or {@code null} when the member is untagged
     * @param explicit whether that tag wraps the member's own encoding rather than replacing its tag
     * @param defaultValue the DEFAULT, which DER forbids encoding, so writing it means omitting the member
     */
    record Member(String name, ExtensionType type, Integer tag, boolean explicit, boolean optional,
            Object defaultValue) {

        public Member(String name, ExtensionType type) {
            this(name, type, null, false, false, null);
        }
    }

    /** An inclusive bound, either end of which may be absent. {@code SIZE} and value ranges share the shape. */
    record Range(BigInteger min, BigInteger max) {

        public static Range of(long min, long max) {
            return new Range(BigInteger.valueOf(min), BigInteger.valueOf(max));
        }

        public boolean admits(BigInteger value) {
            return (min == null || value.compareTo(min) >= 0) && (max == null || value.compareTo(max) <= 0);
        }
    }

    /**
     * A built-in type, optionally constrained. {@code sizes} holds the permitted lengths - a union, because
     * {@code SIZE (8 | 32)} is how RFC 5280 states an iPAddress and a single range cannot say it.
     */
    record Scalar(Primitive primitive, Range valueRange, List<Range> sizes, String pattern) implements ExtensionType {

        public Scalar(Primitive primitive) {
            this(primitive, null, List.of(), null);
        }
    }

    /** A SEQUENCE or SET of declared members, addressed by name. */
    record Structure(List<Member> members, boolean set, Range presentMembers) implements ExtensionType {

        public Structure(List<Member> members) {
            this(members, false, null);
        }
    }

    /** A SEQUENCE OF or SET OF: every element takes the same type. */
    record Repeated(ExtensionType element, boolean set, Range size) implements ExtensionType {

        public Repeated(ExtensionType element) {
            this(element, false, null);
        }
    }

    /** A CHOICE: the value names the alternative it takes. */
    record Choice(List<Member> alternatives) implements ExtensionType {
    }

    /**
     * A member the module does not describe - an ANY, or a type imported from a module the platform was not given. Its
     * value is written as DER and passed through, because nothing here can build it.
     */
    record Opaque(String asn1Name) implements ExtensionType {
    }
}
