package com.otilm.core.extension;

import com.otilm.api.exception.ValidationException;
import com.otilm.core.extension.ExtensionType.Choice;
import com.otilm.core.extension.ExtensionType.Member;
import com.otilm.core.extension.ExtensionType.Opaque;
import com.otilm.core.extension.ExtensionType.Primitive;
import com.otilm.core.extension.ExtensionType.Repeated;
import com.otilm.core.extension.ExtensionType.Scalar;
import com.otilm.core.extension.ExtensionType.Structure;
import java.math.BigInteger;
import java.util.HexFormat;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class Asn1ModuleReaderTest {

    private static ExtensionType read(String body) {
        return Asn1ModuleReader.read("M DEFINITIONS IMPLICIT TAGS ::= BEGIN\n" + body + "\nEND");
    }

    private static String encode(String json, ExtensionType type) throws Exception {
        return HexFormat
                .of()
                .formatHex(JerCodec.encode(new com.fasterxml.jackson.databind.ObjectMapper().readTree(json), type))
                .toUpperCase();
    }

    @Nested
    class ShippedExtensions {

        @Test
        void subjectKeyIdentifierIsABareOctetString() {
            ExtensionType type = read("""
                    SubjectKeyIdentifier ::= KeyIdentifier
                    KeyIdentifier ::= OCTET STRING""");

            assertThat(type).isEqualTo(new Scalar(Primitive.OCTET_STRING));
        }

        @Test
        void basicConstraintsCarriesItsDefaultAndItsLowerBound() throws Exception {
            ExtensionType type = read("""
                    BasicConstraints ::= SEQUENCE {
                         cA                      BOOLEAN DEFAULT FALSE,
                         pathLenConstraint       INTEGER (0..MAX) OPTIONAL }""");

            Structure structure = (Structure) type;
            assertThat(structure.members()).hasSize(2);
            assertThat(structure.members().get(0).defaultValue()).isEqualTo(Boolean.FALSE);
            assertThat(structure.members().get(1).optional()).isTrue();
            assertThat(((Scalar) structure.members().get(1).type()).valueRange().min()).isEqualTo(BigInteger.ZERO);
            assertThat(encode("{\"cA\":true,\"pathLenConstraint\":0}", type)).isEqualTo("30060101FF020100");
        }

        @Test
        void privateKeyUsagePeriodTagsBothMembersImplicitly() throws Exception {
            ExtensionType type = read("""
                    PrivateKeyUsagePeriod ::= SEQUENCE {
                         notBefore       [0]     GeneralizedTime OPTIONAL,
                         notAfter        [1]     GeneralizedTime OPTIONAL }""");

            Member notBefore = ((Structure) type).members().get(0);
            assertThat(notBefore.tag()).isZero();
            assertThat(notBefore.explicit()).isFalse();
            assertThat(encode("{\"notAfter\":\"20271231235959Z\"}", type))
                    .isEqualTo("3011810F32303237313233313233353935395A");
        }

        @Test
        void tlsFeatureIsASequenceOfIntegers() throws Exception {
            ExtensionType type = read("Features ::= SEQUENCE OF INTEGER");

            assertThat(type).isInstanceOf(Repeated.class);
            assertThat(encode("[5]", type)).isEqualTo("3003020105");
        }

        @Test
        void subjectDirectoryAttributesCarriesAnOpaqueValue() {
            ExtensionType type = read("""
                    SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF AttributeSet
                    AttributeSet ::= SEQUENCE {
                         type       OBJECT IDENTIFIER,
                         values     SET SIZE (1..MAX) OF ANY }""");

            Structure attribute = (Structure) ((Repeated) type).element();
            Repeated values = (Repeated) attribute.members().get(1).type();
            assertThat(values.set()).isTrue();
            assertThat(values.element()).isInstanceOf(Opaque.class);
        }
    }

    @Nested
    class Tagging {

        @Test
        void aTagOnAChoiceIsExplicitEvenInAnImplicitModule() {
            // X.680 31.2.7: the tag is what selects a CHOICE alternative, so replacing it would destroy it.
            ExtensionType type = read("""
                    GeneralSubtree ::= SEQUENCE { base [4] Name }
                    Name ::= CHOICE { rdnSequence RDNSequence }
                    RDNSequence ::= SEQUENCE OF ANY""");

            Member base = ((Structure) type).members().get(0);
            assertThat(base.type()).isInstanceOf(Choice.class);
            assertThat(base.explicit()).isTrue();
        }

        @Test
        void aTagOnAnOrdinaryTypeStaysImplicit() {
            ExtensionType type = read("Probe ::= SEQUENCE { dNSName [2] IA5String }");

            assertThat(((Structure) type).members().get(0).explicit()).isFalse();
        }

        @Test
        void aTaggedReferenceToAnUndefinedTypeIsRefusedRatherThanGuessed() {
            // Whether the tag wraps or replaces depends on whether ORAddress is a CHOICE, which is not here.
            assertThatThrownBy(() -> read("GeneralName ::= SEQUENCE { x400Address [3] ORAddress }"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("ORAddress")
                    .hasMessageContaining("tagging cannot be determined");
        }

        @Test
        void anUndefinedTypeThatIsSaidToBeImplicitIsAccepted() {
            ExtensionType type = read("GeneralName ::= SEQUENCE { x400Address [3] IMPLICIT ORAddress }");

            Member member = ((Structure) type).members().get(0);
            assertThat(member.type()).isInstanceOf(Opaque.class);
            assertThat(member.explicit()).isFalse();
        }

        @Test
        void anUntaggedUndefinedTypeIsSimplyOpaque() {
            ExtensionType type = read("Probe ::= SEQUENCE { thing SomethingElse }");

            assertThat(((Structure) type).members().get(0).type()).isEqualTo(new Opaque("SomethingElse"));
        }
    }

    @Nested
    class Constraints {

        @Test
        void aSizeUnionIsKeptAsAUnion() throws Exception {
            // RFC 5280 states an iPAddress as SIZE (8 | 32); one range cannot say it.
            ExtensionType type = read("Addr ::= OCTET STRING (SIZE (4 | 16))");

            assertThat(((Scalar) type).sizes()).hasSize(2);
            assertThat(encode("\"C0000200\"", type)).isEqualTo("0404C0000200");
            assertThatThrownBy(() -> encode("\"C00002\"", type)).isInstanceOf(ValidationException.class);
        }

        @Test
        void aValueRangeReachesTheEncoder() {
            ExtensionType type = read("Tier ::= INTEGER (1..3)");

            assertThatThrownBy(() -> encode("4", type))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("permitted range");
        }
    }

    @Nested
    class Refusals {

        @Test
        void anEmptyModule() {
            assertThatThrownBy(() -> Asn1ModuleReader.read("  "))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("empty");
        }

        @Test
        void aConstructOutsideTheSupportedSubset() {
            assertThatThrownBy(() -> read("Probe ::= SEQUENCE { thing INTEGER (SIZE (1..2)) } (WITH COMPONENTS { x })"))
                    .isInstanceOf(ValidationException.class);
        }

        @Test
        void aTruncatedModule() {
            assertThatThrownBy(() -> Asn1ModuleReader.read("M DEFINITIONS ::= BEGIN Probe ::= SEQUENCE {"))
                    .isInstanceOf(ValidationException.class);
        }
    }
}
