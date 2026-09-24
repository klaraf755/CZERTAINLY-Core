package com.otilm.core.service.cmp.registration;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.core.model.auth.CertificateProtocolInfo;
import com.otilm.core.service.CertificateInternalService;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Attributes a completed CMP registration to its CMP profile in a transaction of its own, independent of the request's
 * outer transaction.
 *
 * <p>
 * The completion itself is already committed and its ISSUE action enqueued when the attribution is written. Written
 * inside the request transaction, the association row would only exist there unflushed: the certificate poll that
 * follows refreshes the certificate and cascades onto that association, which fails on the missing row; and a rollback
 * of the request transaction would drop the attribution of an issued certificate. A separate bean is required because
 * {@code REQUIRES_NEW} advice is skipped on self-invocation within the handler.
 * </p>
 */
@Component
public class CmpRegistrationAttributionWriter {

    private CertificateInternalService certificateService;

    @Autowired
    public void setCertificateService(CertificateInternalService certificateService) {
        this.certificateService = certificateService;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordProtocolAttribution(UUID certificateUuid, UUID cmpProfileUuid)
            throws NotFoundException, AttributeException {
        certificateService.applyProtocolAssociations(certificateUuid, CertificateProtocolInfo.Cmp(cmpProfileUuid));
    }
}
