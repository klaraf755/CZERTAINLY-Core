package com.otilm.core.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.SecretOperationException;
import com.otilm.api.model.client.dashboard.StatisticsDto;
import com.otilm.api.model.connector.secrets.content.SecretContent;
import com.otilm.core.messaging.model.ActionMessage;
import com.otilm.core.security.authz.SecurityFilter;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public interface SecretInternalService extends ResourceExtensionService {

    /**
     * Batch lookup of the latest-version fingerprint for each given secret.
     */
    Map<UUID, String> getLatestFingerprintsByUuid(List<UUID> secretUuids);

    /**
     * Reads a secret's content on behalf of a platform component that holds the secret's UUID in its own configuration,
     * bypassing the resource-level authorization the external accessor applies. There is no caller identity to
     * authorize on such a path — the protocol or scheduler that triggers it never names the secret.
     */
    SecretContent getSecretContentInternal(UUID uuid) throws NotFoundException, ConnectorException, AttributeException;

    void approvalCreatedAction(UUID resourceUuid) throws NotFoundException;

    void processSecretAction(ActionMessage actionMessage, boolean hasApproval, boolean isApproved)
            throws ConnectorException, NotFoundException, AttributeException, JsonProcessingException,
            SecretOperationException;

    Long statisticsSecretCount(SecurityFilter filter);

    StatisticsDto addSecretStatistics(SecurityFilter filter, StatisticsDto dto);
}
