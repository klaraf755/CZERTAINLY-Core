package com.otilm.core.extension;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.api.model.core.oid.SystemOid;
import com.otilm.core.util.StructuredExtensionCodec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The modules Core ships, exercised from text through to DER. The expected encodings come from an independent ASN.1
 * implementation rather than from this code.
 */
class ShippedExtensionModuleTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static ExtensionType type(String oid) {
        return Asn1ModuleReader.read(ExtensionTypes.shippedModule(oid).orElseThrow());
    }

    private static String der(String oid, String json) throws Exception {
        return HexFormat.of().formatHex(JerCodec.encode(MAPPER.readTree(json), type(oid))).toUpperCase();
    }

    @Test
    void everySystemCertificateExtensionShipsAModuleThatReads() {
        // Derived from SystemOid rather than listed, so a system extension added without a module fails the
        // build here instead of shipping with base64-only values. The typed targets are the only exclusion.
        List<SystemOid> extensions = Arrays
                .stream(SystemOid.values())
                .filter(oid -> oid.getCategory() == OidCategory.CERTIFICATE_EXTENSION)
                .filter(oid -> StructuredExtensionCodec.structuredTargetName(oid.getOid()) == null)
                .toList();

        assertThat(extensions).isNotEmpty();
        assertThat(extensions)
                .allSatisfy(oid -> assertThat(ExtensionTypes.shippedModule(oid.getOid()))
                        .as("module for %s (%s)", oid.getOid(), oid.name())
                        .isPresent());
        assertThat(extensions).allSatisfy(oid -> assertThat(type(oid.getOid())).isNotNull());
    }

    @Test
    void keyUsageAndExtendedKeyUsageShipNoModule() {
        // Both have typed mapping targets, which are the only way to set them.
        assertThat(ExtensionTypes.shippedModule("2.5.29.15")).isEmpty();
        assertThat(ExtensionTypes.shippedModule("2.5.29.37")).isEmpty();
    }

    @Test
    void anUndescribedOidResolvesToNothing() {
        assertThat(ExtensionTypes.shippedModule("1.3.6.1.4.1.99999.8.1")).isEqualTo(Optional.empty());
    }

    @Test
    void subjectKeyIdentifier() throws Exception {
        assertThat(der("2.5.29.14", "\"010203\"")).isEqualTo("0403010203");
    }

    @Test
    void basicConstraints() throws Exception {
        assertThat(der("2.5.29.19", "{\"cA\":true,\"pathLenConstraint\":0}")).isEqualTo("30060101FF020100");
        assertThat(der("2.5.29.19", "{}")).isEqualTo("3000");
        assertThatThrownBy(() -> der("2.5.29.19", "{\"cA\":true,\"pathLenConstraint\":-1}"))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    void privateKeyUsagePeriodRequiresAtLeastOneMember() {
        // RFC 3280 4.2.1.4. OPTIONAL on both members cannot say this; the module's WITH COMPONENTS does.
        assertThatThrownBy(() -> der("2.5.29.16", "{}"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("have notBefore, or have notAfter");
    }

    @Test
    void basicConstraintsAllowsAPathLengthOnlyOnACa() throws Exception {
        // RFC 5280 4.2.1.9: pathLenConstraint MUST NOT appear unless cA is asserted. cA written as its default
        // is the same as cA absent, and fails the same way.
        assertThat(der("2.5.29.19", "{\"cA\":false}")).isEqualTo("3000");
        for (String value : List.of("{\"pathLenConstraint\":0}", "{\"cA\":false,\"pathLenConstraint\":0}")) {
            assertThatThrownBy(() -> der("2.5.29.19", value))
                    .as(value)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("omit pathLenConstraint, or have cA = true");
        }
    }

    @Test
    void nameConstraintsRequiresAtLeastOneSubtreeList() {
        // RFC 5280 4.2.1.10: conforming CAs MUST NOT issue an empty Name Constraints.
        assertThatThrownBy(() -> der("2.5.29.30", "{}"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("have permittedSubtrees, or have excludedSubtrees");
    }

    @Test
    void privateKeyUsagePeriodTagsItsMembersImplicitly() throws Exception {
        assertThat(der("2.5.29.16", "{\"notBefore\":\"20260101000000Z\"}"))
                .isEqualTo("3011800F32303236303130313030303030305A");
    }

    @Test
    void tlsFeatureBoundsItsValuesToSixteenBits() throws Exception {
        assertThat(der("1.3.6.1.5.5.7.1.24", "[5]")).isEqualTo("3003020105");
        assertThatThrownBy(() -> der("1.3.6.1.5.5.7.1.24", "[65536]"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("permitted range");
    }

    @Test
    void subjectDirectoryAttributesCarriesOpaqueValues() throws Exception {
        assertThat(der("2.5.29.9", "[{\"type\":\"1.2.3\",\"values\":[\"0C0474657374\"]}]"))
                .isEqualTo("300E300C06022A0331060C0474657374");
        assertThatThrownBy(() -> der("2.5.29.9", "[]"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("0 elements");
    }

    @Test
    void nameConstraintsPermitsADnsSubtree() throws Exception {
        assertThat(der("2.5.29.30", "{\"permittedSubtrees\":[{\"base\":{\"dNSName\":\"demo.example\"}}]}"))
                .isEqualTo("3012A010300E820C64656D6F2E6578616D706C65");
    }

    @Test
    void nameConstraintsSizesAnIpAddressAsAnAddressAndAMask() {
        // Eight octets here, not four: a name constraint carries the address and its mask.
        assertThatThrownBy(() -> der("2.5.29.30", "{\"permittedSubtrees\":[{\"base\":{\"iPAddress\":\"C0000200\"}}]}"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("4 octets");
    }

    @Test
    void nameConstraintsDeclaresNeitherMinimumNorMaximum() {
        // RFC 5280 4.2.1.10: the minimum MUST be zero and the maximum MUST be absent, so neither is writable.
        assertThatThrownBy(() -> der("2.5.29.30",
                "{\"permittedSubtrees\":[{\"base\":{\"dNSName\":\"a.example\"},\"minimum\":1}]}"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("minimum");
    }
}
