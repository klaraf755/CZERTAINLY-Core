package com.otilm.core.integration.logging;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.records.ResourceObjectIdentity;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.logging.AuditLogEnhancer;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

class AuditLogEnhancerITest extends BaseSpringBootTest {

    @Autowired
    private AuditLogEnhancer auditLogEnhancer;

    @Autowired
    private CertificateRepository certificateRepository;

    @Test
    void namesIssuedCertificateBySerialNumber() {
        Certificate issued = certificateRepository
                .save(aCertificate().withCommonName("issued").withSerialNumber("0a1b2c").build());

        List<ResourceObjectIdentity> enriched = auditLogEnhancer
                .enrichObjectIdentities(List.of(new ResourceObjectIdentity(null, issued.getUuid())),
                        Resource.CERTIFICATE);

        assertThat(enriched).containsExactly(new ResourceObjectIdentity("0a1b2c", issued.getUuid()));
    }

    @Test
    void namesCertificateWithoutSerialNumberAsNotIssued() {
        Certificate notIssued = certificateRepository.save(aCertificate().withCommonName("notIssued").build());

        List<ResourceObjectIdentity> enriched = auditLogEnhancer
                .enrichObjectIdentities(List.of(new ResourceObjectIdentity(null, notIssued.getUuid())),
                        Resource.CERTIFICATE);

        assertThat(enriched).containsExactly(new ResourceObjectIdentity("notIssued (Not Issued)", notIssued.getUuid()));
    }
}
