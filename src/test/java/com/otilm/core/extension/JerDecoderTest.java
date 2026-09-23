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
import java.math.BigInteger;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JerDecoderTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static Scalar of(Primitive primitive) {
        return new Scalar(primitive);
    }

    private static final Structure BASIC_CONSTRAINTS = new Structure(List
            .of(new Member("cA", of(Primitive.BOOLEAN), null, false, false, Boolean.FALSE),
                    new Member("pathLenConstraint",
                            new Scalar(Primitive.INTEGER, new Range(BigInteger.ZERO, null), List.of(), null), null,
                            false, true, null)));

    private static final Structure SERVICE_ENTITLEMENT = new Structure(List
            .of(new Member("serviceId", of(Primitive.UTF8_STRING)), new Member("tier", of(Primitive.INTEGER)),
                    new Member("scopes", new Repeated(new Choice(List
                            .of(new Member("name", of(Primitive.IA5_STRING)), new Member("id", of(Primitive.OID)))))),
                    new Member("expires", of(Primitive.GENERALIZED_TIME), 0, false, true, null)));

    // PrivateKeyUsagePeriod: both members optional and identically typed, told apart only by their tags.
    private static final Structure PKUP = new Structure(List
            .of(new Member("notBefore", of(Primitive.GENERALIZED_TIME), 0, false, true, null),
                    new Member("notAfter", of(Primitive.GENERALIZED_TIME), 1, false, true, null)));

    private static JsonNode decode(String hex, ExtensionType type) {
        return JerDecoder.decode(HexFormat.of().parseHex(hex), type);
    }

    private static void roundTrips(String hex, ExtensionType type) {
        assertThat(HexFormat.of().formatHex(JerCodec.encode(decode(hex, type), type)).toUpperCase()).isEqualTo(hex);
    }

    @Test
    void readsBasicConstraints() {
        assertThat(decode("30060101FF020100", BASIC_CONSTRAINTS).toString())
                .isEqualTo("{\"cA\":true,\"pathLenConstraint\":0}");
    }

    @Test
    void anOmittedDefaultComesBackAsItsDefault() {
        // A reader wants the extension's effective content, not a transcript of which octets were present.
        assertThat(decode("3000", BASIC_CONSTRAINTS).toString()).isEqualTo("{\"cA\":false}");
    }

    @Test
    void readsEveryMemberOfTheWorkedExample() {
        assertThat(decode("30350C0B7376632D62696C6C696E670201013012160472656164060A2B06010401868D1F0201"
                + "800F32303237313233313233353935395A", SERVICE_ENTITLEMENT).toString())
                .isEqualTo("{\"serviceId\":\"svc-billing\",\"tier\":1,"
                        + "\"scopes\":[{\"name\":\"read\"},{\"id\":\"1.3.6.1.4.1.99999.2.1\"}],"
                        + "\"expires\":\"20271231235959Z\"}");
    }

    @Test
    void tellsTwoIdenticallyTypedOptionalMembersApartByTheirTags() {
        // The only thing distinguishing notBefore from notAfter is the context tag; without the type this
        // encoding could be either.
        assertThat(decode("3011810F32303237313233313233353935395A", PKUP).toString())
                .isEqualTo("{\"notAfter\":\"20271231235959Z\"}");
        assertThat(decode("3011800F32303237313233313233353935395A", PKUP).toString())
                .isEqualTo("{\"notBefore\":\"20271231235959Z\"}");
    }

    @Test
    void anUndescribedMemberComesBackAsItsOwnDer() {
        Structure withAny = new Structure(
                List.of(new Member("type", of(Primitive.OID)), new Member("value", new Opaque("AttributeValue"))));

        assertThat(decode("300A06022A030C0474657374", withAny).toString())
                .isEqualTo("{\"type\":\"1.2.3\",\"value\":\"0C0474657374\"}");
    }

    @Test
    void decodingThenEncodingReproducesTheSameBytes() {
        roundTrips("30060101FF020100", BASIC_CONSTRAINTS);
        roundTrips("3000", BASIC_CONSTRAINTS);
        roundTrips("30180C0B7376632D62696C6C696E670201013006160472656164", SERVICE_ENTITLEMENT);
        roundTrips("3011810F32303237313233313233353935395A", PKUP);
    }

    @Test
    void anOmittedDefaultBeforeAPresentMemberStillAligns() {
        // SEQUENCE { INTEGER 1 } is a path length with cA defaulted away, not a malformed cA. Keeping the
        // members aligned across an omission is the whole job of matching on type rather than on position.
        assertThat(decode("3003020101", BASIC_CONSTRAINTS).toString())
                .isEqualTo("{\"cA\":false,\"pathLenConstraint\":1}");
    }

    @Test
    void bytesThatAreNotTheDeclaredTypeAreRefused() {
        assertThatThrownBy(() -> decode("020101", BASIC_CONSTRAINTS))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("not the SEQUENCE");
    }

    @Test
    void aMissingRequiredMemberIsRefused() {
        assertThatThrownBy(() -> decode("3000", SERVICE_ENTITLEMENT))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("$.serviceId")
                .hasMessageContaining("missing");
    }

    @Test
    void trailingComponentsTheTypeDoesNotDeclareAreRefused() {
        assertThatThrownBy(() -> decode("30090101FF0201000201FF", BASIC_CONSTRAINTS))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("more members");
    }

    @Test
    void whatIsNotDerIsRefused() {
        assertThatThrownBy(() -> decode("FFFF", BASIC_CONSTRAINTS))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("not valid DER");
    }
}
