package com.czertainly.core.enums;

import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.search.SearchableFields;
import com.czertainly.core.dao.entity.*;
import com.querydsl.core.types.Expression;
import com.querydsl.core.types.Path;
import com.querydsl.jpa.JPAExpressions;
import com.querydsl.jpa.JPQLQuery;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public enum SearchFieldNameEnumQ {

    // Certificate
    COMMON_NAME(QCertificate.certificate.commonName, null, null, "Common Name", SearchFieldTypeEnum.STRING, false,  Resource.CERTIFICATE, null),
    RA_PROFILE_NAME(QRaProfile.raProfile.name, null, List.of(List.of(QCertificate.certificate.raProfile, QRaProfile.raProfile)), "RA Profile", SearchFieldTypeEnum.LIST, true, Resource.CERTIFICATE, Resource.RA_PROFILE),
    CERTIFICATE_STATE(QCertificate.certificate.state, null, null, "State", SearchFieldTypeEnum.LIST, false, Resource.CERTIFICATE, null),
    GROUP_NAME(QGroup.group.name, null, List.of(List.of(QCertificate.certificate.groups, QGroup.group)), "Groups", SearchFieldTypeEnum.LIST, true, Resource.CERTIFICATE, Resource.GROUP),
    OWNER(QOwnerAssociation.ownerAssociation.ownerUsername, null, List.of(List.of(QCertificate.certificate.owner, QOwnerAssociation.ownerAssociation)), "Owner", SearchFieldTypeEnum.LIST, true, Resource.CERTIFICATE, Resource.USER),
    KEY_SIZE(QCertificate.certificate.keySize, null, null, "Key Size", SearchFieldTypeEnum.LIST, false, Resource.CERTIFICATE, null),
    NOT_AFTER(QCertificate.certificate.notAfter, null, null, "Expires At", SearchFieldTypeEnum.DATE, false, Resource.CERTIFICATE, null),
    TRUSTED_CA(QCertificate.certificate.trustedCa, null,null, "Trusted CA", SearchFieldTypeEnum.BOOLEAN, false, Resource.CERTIFICATE, null),

    // Cryptographic Key
    NAME(QCryptographicKeyItem.cryptographicKeyItem.name,null,null,"Name", SearchFieldTypeEnum.STRING, false, Resource.CRYPTOGRAPHIC_KEY, null),
    CK_TOKEN_PROFILE(QTokenProfile.tokenProfile.name, JPAExpressions.selectFrom(QCryptographicKeyItem.cryptographicKeyItem)
            .join(QCryptographicKeyItem.cryptographicKeyItem.cryptographicKey, QCryptographicKey.cryptographicKey)
            .join(QCryptographicKey.cryptographicKey.tokenProfile, QTokenProfile.tokenProfile), List.of(List.of(QCryptographicKeyItem.cryptographicKeyItem.cryptographicKey, QCryptographicKey.cryptographicKey), List.of(QCryptographicKey.cryptographicKey.tokenProfile, QTokenProfile.tokenProfile)),"Token profile", SearchFieldTypeEnum.LIST, false, Resource.CRYPTOGRAPHIC_KEY, Resource.TOKEN_PROFILE),
    CK_GROUP(QGroup.group.name, null, List.of(List.of(QCryptographicKeyItem.cryptographicKeyItem.cryptographicKey, QCryptographicKey.cryptographicKey), List.of(QCryptographicKey.cryptographicKey.groups, QGroup.group)),"Groups", SearchFieldTypeEnum.LIST, true, Resource.CRYPTOGRAPHIC_KEY, Resource.GROUP),

    ;


    private final Expression pathToProperty;

    private final JPQLQuery joinExpression;



    private final List<List<Path>> joins;

    private final String fieldLabel;

    private final SearchFieldTypeEnum fieldTypeEnum;

    private final boolean settable;

    private final Resource resource;

    private final Resource fieldResource;


    public static SearchFieldNameEnumQ findEnum(String propertyName) {
        for (SearchFieldNameEnumQ searchFieldNameEnum : SearchFieldNameEnumQ.values()) {
            if (searchFieldNameEnum.name().equals(propertyName)) {
                return searchFieldNameEnum;
            }
        }
        return null;
    }

}
