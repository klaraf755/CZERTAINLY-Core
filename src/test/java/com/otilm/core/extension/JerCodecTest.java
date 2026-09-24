package com.otilm.core.extension;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.ValidationException;
import com.otilm.core.extension.ExtensionType.Choice;
import com.otilm.core.extension.ExtensionType.Member;
import com.otilm.core.extension.ExtensionType.Opaque;
import com.otilm.core.extension.ExtensionType.Primitive;
import com.otilm.core.extension.ExtensionType.Range;
import com.otilm.core.extension.ExtensionType.Repeated;
import com.otilm.core.extension.ExtensionType.Scalar;
import com.otilm.core.extension.ExtensionType.Structure;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Golden vectors come from an independent JER/DER implementation (asn1tools) rather than from this codec, so a shared
 * misreading of X.697 cannot make them pass.
 */
class JerCodecTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static Scalar of(Primitive primitive) {
        return new Scalar(primitive);
    }

    private static String der(String json, ExtensionType type) throws Exception {
        JsonNode value = MAPPER.readTree(json);
        return HexFormat.of().formatHex(JerCodec.encode(value, type)).toUpperCase();
    }

    // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX) OPTIONAL }
    private static final Structure BASIC_CONSTRAINTS = new Structure(List
            .of(new Member("cA", of(Primitive.BOOLEAN), null, false, false, Boolean.FALSE),
                    new Member(
                            "pathLenConstraint", new Scalar(Primitive.INTEGER,
                                    List.of(new Range(java.math.BigInteger.ZERO, null)), List.of()),
                            null, false, true, null)));

    // ServiceEntitlement, the worked example
    private static final Structure SERVICE_ENTITLEMENT = new Structure(List
            .of(new Member("serviceId", new Scalar(Primitive.UTF8_STRING, List.of(), List.of(Range.of(5, 32)))),
                    new Member("tier", new Scalar(Primitive.INTEGER, List.of(Range.of(1, 3)), List.of())),
                    new Member("scopes", new Repeated(new Choice(
                            List.of(new Member("name", of(Primitive.IA5_STRING)), new Member("id", of(Primitive.OID)))),
                            false, List.of(Range.of(1, 8)))),
                    new Member("expires", of(Primitive.GENERALIZED_TIME), 0, false, true, null)));

    @Nested
    class GoldenVectors {

        @Test
        void basicConstraintsCaTruePathLenZero() throws Exception {
            assertThat(der("{\"cA\":true,\"pathLenConstraint\":0}", BASIC_CONSTRAINTS)).isEqualTo("30060101FF020100");
        }

        @Test
        void anEndEntityIsTheEmptySequence() throws Exception {
            assertThat(der("{}", BASIC_CONSTRAINTS)).isEqualTo("3000");
        }

        @Test
        void writingADefaultOmitsItRatherThanEncodingIt() throws Exception {
            // DER forbids encoding a DEFAULT value, so cA false is the same encoding as cA absent.
            assertThat(der("{\"cA\":false}", BASIC_CONSTRAINTS)).isEqualTo("3000");
        }

        @Test
        void serviceEntitlementWithEveryMember() throws Exception {
            assertThat(der("""
                    {"serviceId":"svc-billing","tier":1,
                     "scopes":[{"name":"read"},{"id":"1.3.6.1.4.1.99999.2.1"}],
                     "expires":"20271231235959Z"}
                    """, SERVICE_ENTITLEMENT))
                    .isEqualTo("30350C0B7376632D62696C6C696E670201013012160472656164060A2B0601040186"
                            + "8D1F0201800F32303237313233313233353935395A");
        }

        @Test
        void anOmittedOptionalMemberSimplyDoesNotAppear() throws Exception {
            assertThat(der("{\"serviceId\":\"svc-billing\",\"tier\":1,\"scopes\":[{\"name\":\"read\"}]}",
                    SERVICE_ENTITLEMENT)).isEqualTo("30180C0B7376632D62696C6C696E670201013006160472656164");
        }

        @Test
        void anImplicitlyTaggedOctetStringReplacesItsTag() throws Exception {
            Structure addr = new Structure(
                    List.of(new Member("ip", of(Primitive.OCTET_STRING), 7, false, false, null)));

            assertThat(der("{\"ip\":\"C0000200\"}", addr)).isEqualTo("30068704C0000200");
        }

        @Test
        void aSequenceOfTakesAnArray() throws Exception {
            assertThat(der("[5]", new Repeated(of(Primitive.INTEGER)))).isEqualTo("3003020105");
        }
    }

    @Nested
    class Refusals {

        @Test
        void aMemberTheExtensionDoesNotDeclare() {
            assertThatThrownBy(() -> der(
                    "{\"serviceId\":\"svc-x\",\"tier\":1," + "\"scopes\":[{\"name\":\"a\"}],\"region\":\"eu\"}",
                    SERVICE_ENTITLEMENT))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("$.region")
                    .hasMessageContaining("not a member");
        }

        @Test
        void aMissingRequiredMember() {
            assertThatThrownBy(() -> der("{\"serviceId\":\"svc-x\"}", SERVICE_ENTITLEMENT))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("$.tier")
                    .hasMessageContaining("required");
        }

        @Test
        void aValueOutsideTheModulesRange() {
            assertThatThrownBy(() -> der("{\"serviceId\":\"svc-x\",\"tier\":4,\"scopes\":[{\"name\":\"a\"}]}",
                    SERVICE_ENTITLEMENT))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("$.tier")
                    .hasMessageContaining("permitted range");
        }

        @Test
        void aStringOutsideTheModulesSize() {
            assertThatThrownBy(
                    () -> der("{\"serviceId\":\"svc\",\"tier\":1,\"scopes\":[{\"name\":\"a\"}]}", SERVICE_ENTITLEMENT))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("$.serviceId")
                    .hasMessageContaining("3 characters");
        }

        @Test
        void anAlternativeTheChoiceDoesNotOffer() {
            assertThatThrownBy(() -> der("{\"serviceId\":\"svc-x\",\"tier\":1,\"scopes\":[{\"nickname\":\"a\"}]}",
                    SERVICE_ENTITLEMENT))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("$.scopes[0].nickname")
                    .hasMessageContaining("not an alternative");
        }

        @Test
        void tooManyElementsForTheModulesSize() {
            String scopes = "{\"name\":\"a\"},".repeat(9);
            assertThatThrownBy(() -> der("{\"serviceId\":\"svc-x\",\"tier\":1,\"scopes\":["
                    + scopes.substring(0, scopes.length() - 1) + "]}", SERVICE_ENTITLEMENT))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("$.scopes")
                    .hasMessageContaining("9 elements");
        }
    }

    @Nested
    class OpaqueMembers {

        @Test
        void anUndescribedMemberCarriesItsOwnDer() throws Exception {
            Structure withAny = new Structure(
                    List.of(new Member("type", of(Primitive.OID)), new Member("value", new Opaque("AttributeValue"))));

            assertThat(der("{\"type\":\"1.2.3\",\"value\":\"0C0474657374\"}", withAny))
                    .isEqualTo("300A06022A030C0474657374");
        }

        @Test
        void bytesThatAreNotDerAreRefused() {
            Structure withAny = new Structure(List.of(new Member("value", new Opaque("AttributeValue"))));

            assertThatThrownBy(() -> der("{\"value\":\"FFFF\"}", withAny))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("AttributeValue");
        }
    }

    @Nested
    class WrittenOrBytes {

        @Test
        void everyJerRootFormIsWritten() {
            for (String value : List
                    .of("{\"a\":1}", "[1]", "\"010203\"", "5", "-1", "true", "false", "null", "  {\"a\":1}", "\n[1]")) {
                assertThat(JerCodec.looksWritten(value)).as(value).isTrue();
            }
        }

        @Test
        void base64DerIsBytes() {
            // First characters of base64 for the tag bytes an extension value can start with.
            // "1AEA" is D4 01 00, a private-class tag: base64 that begins with a digit and must still be bytes.
            for (String value : List
                    .of("MAYBAf8CAQA=", "BAMBAgM=", "AgEB", "AQH/", "oA==", "gA8y", "MBIWBA==", "1AEA")) {
                assertThat(JerCodec.looksWritten(value)).as(value).isFalse();
            }
            assertThat(JerCodec.looksWritten("")).isFalse();
            assertThat(JerCodec.looksWritten(null)).isFalse();
        }
    }

    @Nested
    class ComponentConstraints {

        private final Structure atLeastOne = new Structure(
                List
                        .of(new Member("a", of(Primitive.INTEGER), 0, false, true, null),
                                new Member("b", of(Primitive.INTEGER), 1, false, true, null)),
                false,
                List
                        .of(List.of(new ExtensionType.ComponentRule("a", ExtensionType.Presence.PRESENT, null)),
                                List.of(new ExtensionType.ComponentRule("b", ExtensionType.Presence.PRESENT, null))));

        @Test
        void oneSatisfiedAlternativeIsEnough() throws Exception {
            assertThat(der("{\"b\":2}", atLeastOne)).isEqualTo("3003810102");
        }

        @Test
        void noSatisfiedAlternativeIsRefusedNamingThem() {
            assertThatThrownBy(() -> der("{}", atLeastOne))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("must have a, or have b");
        }
    }

    @Nested
    class WrittenNull {

        private final Structure withMarker = new Structure(
                List.of(new Member("marker", of(Primitive.NULL), null, false, true, null)));

        @Test
        void aWrittenNullIsAnAsn1Null_notAnOmission() throws Exception {
            // JSON null is the JER value of NULL; {"marker":null} encodes 05 00 where {} encodes nothing.
            assertThat(der("{\"marker\":null}", withMarker)).isEqualTo("30020500");
            assertThat(der("{}", withMarker)).isEqualTo("3000");
        }

        @Test
        void aWrittenNullForAnotherTypeIsRefusedByThatType() {
            Structure optionalInteger = new Structure(
                    List.of(new Member("tier", of(Primitive.INTEGER), null, false, true, null)));

            assertThatThrownBy(() -> der("{\"tier\":null}", optionalInteger))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("$.tier")
                    .hasMessageContaining("whole number");
        }
    }
}
