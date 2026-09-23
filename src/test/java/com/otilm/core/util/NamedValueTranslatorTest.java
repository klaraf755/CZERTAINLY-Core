package com.otilm.core.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.ValidationException;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class NamedValueTranslatorTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String SERVICE_ENTITLEMENT = """
            {"type":"object","required":["sequence"],"properties":{"sequence":{
              "type":"array","minItems":3,"maxItems":4,"prefixItems":[
                {"title":"serviceId","type":"object","required":["utf8String"],
                 "properties":{"utf8String":{"type":"string","pattern":"^svc-[a-z0-9-]+$"}}},
                {"title":"tier","type":"object","required":["integer"],
                 "properties":{"integer":{"type":"integer","minimum":1,"maximum":3}}},
                {"title":"scopes","type":"object","required":["sequence"],
                 "properties":{"sequence":{"type":"array","items":{"oneOf":[
                   {"title":"name","type":"object","required":["ia5String"]},
                   {"title":"id","type":"object","required":["oid"]}]}}}},
                {"title":"expires","type":"object","required":["tagged"],
                 "properties":{"tagged":{"type":"object","required":["tagNo","explicit","value"],
                   "properties":{"tagNo":{"const":0},"explicit":{"const":false},
                     "value":{"type":"object","required":["generalizedTime"]}}}}}
              ],"items":false}}}
            """;

    private static JsonNode schema() throws Exception {
        return MAPPER.readTree(SERVICE_ENTITLEMENT);
    }

    private static NamedValueTranslator.Translated translate(String named) throws Exception {
        return NamedValueTranslator.translate(MAPPER.readTree(named), schema());
    }

    @Test
    void translatesEveryMemberIncludingTheTaggedOptional() throws Exception {
        var result = translate("""
                {"serviceId":"svc-billing","tier":1,
                 "scopes":[{"name":"read"},{"id":"1.3.6.1.4.1.99999.2.1"}],
                 "expires":"20271231235959Z"}
                """);

        assertThat(result.tree().toString())
                .isEqualTo("{\"sequence\":[{\"utf8String\":\"svc-billing\"},{\"integer\":1},"
                        + "{\"sequence\":[{\"ia5String\":\"read\"},{\"oid\":\"1.3.6.1.4.1.99999.2.1\"}]},"
                        + "{\"tagged\":{\"tagNo\":0,\"explicit\":false,"
                        + "\"value\":{\"generalizedTime\":\"20271231235959Z\"}}}]}");
        assertThat(AsnJsonCodec.encode(result.tree())).isNotEmpty();
    }

    @Test
    void anOmittedOptionalMemberSimplyDoesNotAppear() throws Exception {
        var result = translate("{\"serviceId\":\"svc-billing\",\"tier\":1,\"scopes\":[{\"name\":\"read\"}]}");

        assertThat(result.tree().path("sequence")).hasSize(3);
    }

    @Test
    void aMemberTheExtensionDoesNotDeclareIsRefused() throws Exception {
        assertThatThrownBy(() -> translate("{\"serviceId\":\"svc-x\",\"region\":\"eu\"}"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("$.region")
                .hasMessageContaining("no member of that name");
    }

    @Test
    void anAlternativeTheChoiceDoesNotOfferIsRefused() throws Exception {
        assertThatThrownBy(() -> translate("{\"serviceId\":\"svc-x\",\"tier\":1,\"scopes\":[{\"nickname\":\"read\"}]}"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("$.scopes[0].nickname")
                .hasMessageContaining("no alternative of that name");
    }

    @Test
    void aSchemaThatDoesNotPinItsTagIsRefusedRatherThanGuessed() throws Exception {
        JsonNode loose = MAPPER.readTree("""
                {"type":"object","required":["sequence"],"properties":{"sequence":{"prefixItems":[
                  {"title":"expires","type":"object","required":["tagged"]}]}}}
                """);

        assertThatThrownBy(
                () -> NamedValueTranslator.translate(MAPPER.readTree("{\"expires\":\"20271231235959Z\"}"), loose))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("does not pin its tag");
    }

    @Test
    void aTreeIsNotMistakenForANamedValue() throws Exception {
        assertThat(NamedValueTranslator.isNamedForm(MAPPER.readTree("{\"sequence\":[]}"))).isFalse();
        assertThat(NamedValueTranslator.isNamedForm(MAPPER.readTree("{\"serviceId\":\"svc-x\"}"))).isTrue();
        assertThat(NamedValueTranslator.isNamedForm(MAPPER.readTree("{\"integer\":1}"))).isFalse();
    }

    @Test
    void aTreeLocationReportsTheNameItsAuthorWrote() throws Exception {
        Map<String, String> paths = translate(
                "{\"serviceId\":\"svc-billing\",\"tier\":9,\"scopes\":[{\"name\":\"read\"}]}").namedPaths();

        assertThat(NamedValueTranslator.namedPath(paths, "$.sequence[1].integer")).isEqualTo("$.tier");
        assertThat(NamedValueTranslator.namedPath(paths, "$.sequence[2].sequence[0]")).isEqualTo("$.scopes[0].name");
    }
}
