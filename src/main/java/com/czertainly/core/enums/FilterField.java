package com.czertainly.core.enums;

import com.czertainly.api.model.common.enums.IPlatformEnum;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyFormat;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.compliance.ComplianceStatus;
import com.czertainly.api.model.core.cryptography.key.KeyState;
import com.czertainly.api.model.core.cryptography.key.KeyUsage;
import com.czertainly.api.model.core.discovery.DiscoveryStatus;
import com.czertainly.core.dao.entity.*;
import jakarta.persistence.metamodel.Attribute;

import java.util.Arrays;
import java.util.List;

public enum FilterField {

    // Certificate
    COMMON_NAME(Resource.CERTIFICATE, null, null, Certificate_.commonName, "Common Name", SearchFieldTypeEnum.STRING),
    SERIAL_NUMBER(Resource.CERTIFICATE, null, null, Certificate_.serialNumber, "Serial Number", SearchFieldTypeEnum.STRING),
    RA_PROFILE_NAME(Resource.CERTIFICATE, Resource.RA_PROFILE, List.of(Certificate_.raProfile), RaProfile_.name, "RA Profile", SearchFieldTypeEnum.LIST, null, null, true),
    CERTIFICATE_STATE(Resource.CERTIFICATE, null, null, Certificate_.state, "State", SearchFieldTypeEnum.LIST, CertificateState.class),
    CERTIFICATE_VALIDATION_STATUS(Resource.CERTIFICATE, null, null, Certificate_.validationStatus, "Validation status", SearchFieldTypeEnum.LIST, CertificateValidationStatus.class),
    COMPLIANCE_STATUS(Resource.CERTIFICATE, null, null, Certificate_.complianceStatus, "Compliance Status", SearchFieldTypeEnum.LIST, ComplianceStatus.class),
    GROUP_NAME(Resource.CERTIFICATE, Resource.GROUP, List.of(Certificate_.groups), Group_.name, "Groups", SearchFieldTypeEnum.LIST, null, null, true),
    CERT_LOCATION_NAME(Resource.CERTIFICATE, Resource.LOCATION, List.of(Certificate_.locations, CertificateLocation_.location), Location_.name, "Locations", SearchFieldTypeEnum.LIST),
    OWNER(Resource.CERTIFICATE, Resource.USER, List.of(Certificate_.owner), OwnerAssociation_.ownerUsername, "Owner", SearchFieldTypeEnum.LIST, null, null, true),
    ISSUER_COMMON_NAME(Resource.CERTIFICATE, null, null, Certificate_.issuerCommonName, "Issuer Common Name", SearchFieldTypeEnum.STRING),
    SIGNATURE_ALGORITHM(Resource.CERTIFICATE, null, null, Certificate_.signatureAlgorithm, "Signature Algorithm", SearchFieldTypeEnum.LIST),
    FINGERPRINT(Resource.CERTIFICATE, null, null, Certificate_.fingerprint, "Fingerprint", SearchFieldTypeEnum.STRING),
    NOT_AFTER(Resource.CERTIFICATE, null, null, Certificate_.notAfter, "Expires At", SearchFieldTypeEnum.DATE),
    NOT_BEFORE(Resource.CERTIFICATE, null, null, Certificate_.notBefore, "Valid From", SearchFieldTypeEnum.DATE),
    PUBLIC_KEY_ALGORITHM(Resource.CERTIFICATE, null, null, Certificate_.publicKeyAlgorithm, "Public Key Algorithm", SearchFieldTypeEnum.LIST),
    KEY_SIZE(Resource.CERTIFICATE, null, null, Certificate_.keySize, "Key Size", SearchFieldTypeEnum.LIST),
    KEY_USAGE(Resource.CERTIFICATE, null, null, Certificate_.keyUsage, "Key Usage", SearchFieldTypeEnum.LIST),
    BASIC_CONSTRAINTS(Resource.CERTIFICATE, null, null, Certificate_.basicConstraints, "Basic Constraints", SearchFieldTypeEnum.LIST),
    SUBJECT_ALTERNATIVE_NAMES(Resource.CERTIFICATE, null, null, Certificate_.subjectAlternativeNames, "Subject Alternative Name", SearchFieldTypeEnum.STRING),
    SUBJECTDN(Resource.CERTIFICATE, null, null, Certificate_.subjectDn, "Subject DN", SearchFieldTypeEnum.STRING),
    ISSUERDN(Resource.CERTIFICATE, null, null, Certificate_.issuerDn, "Issuer DN", SearchFieldTypeEnum.STRING),
    ISSUER_SERIAL_NUMBER(Resource.CERTIFICATE, null, null, Certificate_.issuerSerialNumber, "Issuer Serial Number", SearchFieldTypeEnum.STRING),
    OCSP_VALIDATION(Resource.CERTIFICATE, null, null, Certificate_.certificateValidationResult, "OCSP Validation", SearchFieldTypeEnum.LIST, CertificateValidationStatus.class),
    CRL_VALIDATION(Resource.CERTIFICATE, null, null, Certificate_.certificateValidationResult, "CRL Validation", SearchFieldTypeEnum.LIST, CertificateValidationStatus.class),
    SIGNATURE_VALIDATION(Resource.CERTIFICATE, null, null, Certificate_.certificateValidationResult, "Signature Validation", SearchFieldTypeEnum.LIST, CertificateValidationStatus.class),
    PRIVATE_KEY(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY, List.of(Certificate_.key, CryptographicKey_.items), CryptographicKeyItem_.type, "Has private key", SearchFieldTypeEnum.BOOLEAN, null, KeyType.PRIVATE_KEY, false),
    TRUSTED_CA(Resource.CERTIFICATE, null, null, Certificate_.trustedCa, "Trusted CA", SearchFieldTypeEnum.BOOLEAN),

    // Cryptographic Key
    CKI_NAME(Resource.CRYPTOGRAPHIC_KEY, null, null, CryptographicKeyItem_.name, "Name", SearchFieldTypeEnum.STRING),
    CKI_TYPE(Resource.CRYPTOGRAPHIC_KEY, null, null, CryptographicKeyItem_.type, "Key type", SearchFieldTypeEnum.LIST, KeyType.class, null, false),
    CKI_FORMAT(Resource.CRYPTOGRAPHIC_KEY, null, null, CryptographicKeyItem_.format, "Key format", SearchFieldTypeEnum.LIST, KeyFormat.class, null, false),
    CKI_STATE(Resource.CRYPTOGRAPHIC_KEY, null, null, CryptographicKeyItem_.state, "State", SearchFieldTypeEnum.LIST, KeyState.class, null, false),
    CKI_CRYPTOGRAPHIC_ALGORITHM(Resource.CRYPTOGRAPHIC_KEY, null, null, CryptographicKeyItem_.keyAlgorithm, "Cryptographic algorithm", SearchFieldTypeEnum.LIST, KeyAlgorithm.class, null, false),
    CKI_USAGE(Resource.CRYPTOGRAPHIC_KEY, null, null, CryptographicKeyItem_.usage, "Key Usage", SearchFieldTypeEnum.LIST, KeyUsage.class, null, false),
    CKI_LENGTH(Resource.CRYPTOGRAPHIC_KEY, null, null, CryptographicKeyItem_.length, "Key Size", SearchFieldTypeEnum.NUMBER),
    CK_TOKEN_PROFILE(Resource.CRYPTOGRAPHIC_KEY, Resource.TOKEN_PROFILE, List.of(CryptographicKeyItem_.cryptographicKey, CryptographicKey_.tokenProfile), TokenProfile_.name, "Token profile", SearchFieldTypeEnum.LIST),
    CK_TOKEN_INSTANCE(Resource.CRYPTOGRAPHIC_KEY, Resource.TOKEN, List.of(CryptographicKeyItem_.cryptographicKey, CryptographicKey_.tokenInstanceReference), TokenInstanceReference_.name, "Token instance", SearchFieldTypeEnum.LIST),
    CK_GROUP(Resource.CRYPTOGRAPHIC_KEY, Resource.GROUP, List.of(CryptographicKeyItem_.cryptographicKey, CryptographicKey_.groups), Group_.name, "Groups", SearchFieldTypeEnum.LIST, null, null, true),
    CK_OWNER(Resource.CRYPTOGRAPHIC_KEY, Resource.USER, List.of(CryptographicKeyItem_.cryptographicKey, CryptographicKey_.owner), OwnerAssociation_.ownerUsername, "Owner", SearchFieldTypeEnum.LIST, null, null, true),

    // Discovery
    DISCOVERY_NAME(Resource.DISCOVERY, null, null, DiscoveryHistory_.name, "Name", SearchFieldTypeEnum.STRING),
    DISCOVERY_START_TIME(Resource.DISCOVERY, null, null, DiscoveryHistory_.startTime, "Start time", SearchFieldTypeEnum.DATETIME),
    DISCOVERY_END_TIME(Resource.DISCOVERY, null, null, DiscoveryHistory_.endTime, "End time", SearchFieldTypeEnum.DATETIME),
    DISCOVERY_STATUS(Resource.DISCOVERY, null, null, DiscoveryHistory_.status, "Status", SearchFieldTypeEnum.LIST, DiscoveryStatus.class, null, false),
    DISCOVERY_TOTAL_CERT_DISCOVERED(Resource.DISCOVERY, null, null, DiscoveryHistory_.totalCertificatesDiscovered, "Total certificate discovered", SearchFieldTypeEnum.NUMBER),
    DISCOVERY_CONNECTOR_NAME(Resource.DISCOVERY, null, null, DiscoveryHistory_.connectorName, "Discovery provider", SearchFieldTypeEnum.LIST),
    DISCOVERY_KIND(Resource.DISCOVERY, null, null, DiscoveryHistory_.kind, "Kind", SearchFieldTypeEnum.STRING),

    // Entity
    ENTITY_NAME(Resource.ENTITY, null, null, EntityInstanceReference_.name, "Name", SearchFieldTypeEnum.STRING),
    ENTITY_CONNECTOR_NAME(Resource.ENTITY, null, null, EntityInstanceReference_.connectorName, "Entity provider", SearchFieldTypeEnum.LIST),
    ENTITY_KIND(Resource.ENTITY, null, null, EntityInstanceReference_.kind, "Kind", SearchFieldTypeEnum.LIST),

    // Location
    LOCATION_NAME(Resource.LOCATION, null, null, Location_.name, "Name", SearchFieldTypeEnum.STRING),
    LOCATION_ENTITY_INSTANCE(Resource.LOCATION, null, null, Location_.entityInstanceName, "Entity instance", SearchFieldTypeEnum.LIST),
    LOCATION_ENABLED(Resource.LOCATION, null, null, Location_.enabled, "Enabled", SearchFieldTypeEnum.BOOLEAN),
    LOCATION_SUPPORT_MULTIPLE_ENTRIES(Resource.LOCATION, null, null, Location_.supportMultipleEntries, "Support multiple entries", SearchFieldTypeEnum.BOOLEAN),
    LOCATION_SUPPORT_KEY_MANAGEMENT(Resource.LOCATION, null, null, Location_.supportKeyManagement, "Support key management", SearchFieldTypeEnum.BOOLEAN),
    ;

    private static final FilterField[] VALUES;

    static {
        VALUES = values();
    }

    private final Resource rootResource;
    private final Resource fieldResource;
    private final List<Attribute> joinAttributes;
    private final Attribute fieldAttribute;
    private final SearchFieldTypeEnum type;
    private final String label;
    private final Class<? extends IPlatformEnum> enumClass;
    private final boolean settable;
    private final Object expectedValue;

    FilterField(final Resource rootResource, final Resource fieldResource, final List<Attribute> joinAttributes, final Attribute fieldAttribute, final String label, final SearchFieldTypeEnum type) {
        this(rootResource, fieldResource, joinAttributes, fieldAttribute, label, type, null, null, false);
    }

    FilterField(final Resource rootResource, final Resource fieldResource, final List<Attribute> joinAttributes, final Attribute fieldAttribute, final String label, final SearchFieldTypeEnum type, final Class<? extends IPlatformEnum> enumClass) {
        this(rootResource, fieldResource, joinAttributes, fieldAttribute, label, type, enumClass, null, false);
    }

    FilterField(final Resource rootResource, final Resource fieldResource, final List<Attribute> joinAttributes, final Attribute fieldAttribute, final String label, final SearchFieldTypeEnum type, final Class<? extends IPlatformEnum> enumClass, final Object expectedValue, final boolean settable) {
        this.rootResource = rootResource;
        this.fieldResource = fieldResource;
        this.joinAttributes = joinAttributes == null ? List.of() : joinAttributes;
        this.fieldAttribute = fieldAttribute;
        this.label = label;
        this.type = type;
        this.enumClass = enumClass;
        this.settable = settable;
        this.expectedValue = expectedValue;
    }

    public Resource getRootResource() {
        return rootResource;
    }

    public Resource getFieldResource() {
        return fieldResource;
    }

    public List<Attribute> getJoinAttributes() {
        return joinAttributes;
    }

    public Attribute getFieldAttribute() {
        return fieldAttribute;
    }

    public SearchFieldTypeEnum getType() {
        return type;
    }

    public String getLabel() {
        return label;
    }

    public Class<? extends IPlatformEnum> getEnumClass() {
        return enumClass;
    }

    public Object getExpectedValue() {
        return expectedValue;
    }

    public boolean isSettable() {
        return settable;
    }

    public static List<FilterField> getEnumsForResource(Resource resource) {
        return Arrays.stream(VALUES).filter(filterField -> filterField.rootResource == resource).toList();
    }

    }