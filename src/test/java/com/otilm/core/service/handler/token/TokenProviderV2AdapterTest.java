package com.otilm.core.service.handler.token;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v2.CryptographicOperationsSyncApiClient;
import com.otilm.api.interfaces.client.v2.TokenSyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.cryptography.operations.RandomDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.RandomDataResponseDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.cryptography.v2.TokenProfileScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.RandomDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.RandomDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.token.TokenScopedRequestV2Dto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.model.connector.ImmutableConnectorFullModel;
import com.otilm.core.model.crypto.ImmutableTokenInstanceBasicModel;
import com.otilm.core.model.crypto.ImmutableTokenProfileBasicModel;
import com.otilm.core.service.handler.OperationAttributeResolver;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class TokenProviderV2AdapterTest {

    private TokenSyncApiClient tokenApiClient;
    private CryptographicOperationsSyncApiClient operationsClient;
    private TokenProviderV2Adapter adapter;
    private ImmutableTokenInstanceBasicModel token;
    private AttributeEngine attributeEngine;
    private OperationAttributeResolver operationAttributeResolver;

    @BeforeEach
    void setUp() throws Exception {
        UUID connectorUuid = UUID.randomUUID();
        ImmutableConnectorFullModel connector = connector(connectorUuid);
        ConnectorApiFactory connectorApiFactory = mock(ConnectorApiFactory.class);
        attributeEngine = mock(AttributeEngine.class);
        operationAttributeResolver = mock(OperationAttributeResolver.class);
        tokenApiClient = mock(TokenSyncApiClient.class);
        operationsClient = mock(CryptographicOperationsSyncApiClient.class);
        when(connectorApiFactory.getTokenInstanceApiClientV2(connector)).thenReturn(tokenApiClient);
        when(attributeEngine.getRequestObjectDataAttributesContent(any())).thenReturn(List.of());
        when(operationAttributeResolver.resolveForConnectorRequestAsSystem(connectorUuid, List.of()))
                .thenReturn(List.of());
        adapter = new TokenProviderV2Adapter(connectorApiFactory, attributeEngine, operationAttributeResolver,
                connector, operationsClient);
        token = token(connectorUuid);
    }

    @Test
    void listSupportedKeyUsages_throwsConnectorException_forNullResponse() throws Exception {
        // given
        when(tokenApiClient.listTokenProfileKeyUsages(any(), any())).thenReturn(null);

        // when
        Executable listUsages = () -> adapter.listSupportedKeyUsages(token);

        // then
        ConnectorException exception = assertThrows(ConnectorException.class, listUsages);
        assertTrue(exception.getMessage().contains("Connector returned no Key Usages"));
    }

    @Test
    void listSupportedKeyRequestTypes_resolvesTokenAndProfileContext() throws Exception {
        // given
        var profile = profile();
        List<RequestAttribute> resolvedToken = List.of(requestAttribute("resolved-token"));
        List<RequestAttribute> resolvedProfile = List.of(requestAttribute("resolved-profile"));
        stubAttributes(Resource.TOKEN, token.uuid(), List.of(requestAttribute("stored-token")), resolvedToken);
        stubAttributes(Resource.TOKEN_PROFILE, profile.uuid(), List.of(requestAttribute("stored-profile")),
                resolvedProfile);
        List<KeyRequestType> supportedTypes = List.of(KeyRequestType.KEY_PAIR);
        when(tokenApiClient.listSupportedKeyRequestTypes(any(), any())).thenReturn(supportedTypes);

        // when
        List<KeyRequestType> types = adapter.listSupportedKeyRequestTypes(profile);

        // then
        assertEquals(supportedTypes, types);
        ArgumentCaptor<TokenProfileScopedRequestV2Dto> request = ArgumentCaptor
                .forClass(TokenProfileScopedRequestV2Dto.class);
        verify(tokenApiClient).listSupportedKeyRequestTypes(any(), request.capture());
        assertEquals(resolvedToken, request.getValue().getTokenAttributes());
        assertEquals(resolvedProfile, request.getValue().getTokenProfileAttributes());
        assertEquals(Set.copyOf(profile.usages()), request.getValue().getKeyUsages());
    }

    @Test
    void listSupportedKeyRequestTypes_stopsWhenResolutionFails() throws Exception {
        // given
        var profile = profile();
        List<RequestAttribute> storedProfile = List.of(requestAttribute("unresolvable-profile"));
        ObjectAttributeContentInfo profileScope = ObjectAttributeContentInfo
                .builder(Resource.TOKEN_PROFILE, profile.uuid())
                .connector(token.connectorUuid())
                .build();
        when(attributeEngine.getRequestObjectDataAttributesContent(profileScope)).thenReturn(storedProfile);
        ConnectorException failure = new ConnectorException("Stored profile credential cannot be resolved");
        when(operationAttributeResolver.resolveForConnectorRequestAsSystem(token.connectorUuid(), storedProfile))
                .thenThrow(failure);

        // when
        Executable listTypes = () -> adapter.listSupportedKeyRequestTypes(profile);

        // then
        assertSame(failure, assertThrows(ConnectorException.class, listTypes));
        verifyNoInteractions(tokenApiClient);
    }

    @Test
    void listRandomAttributes_sendsTokenScopeAndPersistsDefinitions() throws Exception {
        // given
        List<RequestAttribute> resolvedToken = List.of(requestAttribute("resolved-token"));
        stubAttributes(Resource.TOKEN, token.uuid(), List.of(requestAttribute("stored-token")), resolvedToken);
        List<BaseAttribute> definitions = List.of(new DataAttributeV2());
        when(operationsClient.listRandomAttributes(any(), any())).thenReturn(definitions);

        // when
        List<BaseAttribute> result = adapter.listRandomAttributes(token);

        // then
        assertSame(definitions, result);
        ArgumentCaptor<TokenScopedRequestV2Dto> request = ArgumentCaptor.forClass(TokenScopedRequestV2Dto.class);
        verify(operationsClient).listRandomAttributes(any(), request.capture());
        assertSame(resolvedToken, request.getValue().getTokenAttributes());
        verify(attributeEngine).updateDataAttributeDefinitions(token.connectorUuid(), null, definitions);
    }

    @Test
    void randomData_validatesAttributesAgainstSchema_thenForwardsLengthAndEncodesData() throws Exception {
        // given
        List<BaseAttribute> definitions = List.of(new DataAttributeV2());
        when(operationsClient.listRandomAttributes(any(), any())).thenReturn(definitions);
        RandomDataResponseV2Dto connectorResponse = new RandomDataResponseV2Dto();
        connectorResponse.setData(new byte[]{9, 8});
        when(operationsClient.randomData(any(), any())).thenReturn(connectorResponse);
        RandomDataRequestDto request = new RandomDataRequestDto();
        request.setLength(2);
        request.setAttributes(List.of(requestAttribute("length-hint")));

        // when
        RandomDataResponseDto response = adapter.randomData(token, request);

        // then
        verify(attributeEngine)
                .validateUpdateDataAttributes(token.connectorUuid(), null, definitions, request.getAttributes());
        ArgumentCaptor<RandomDataRequestV2Dto> sent = ArgumentCaptor.forClass(RandomDataRequestV2Dto.class);
        verify(operationsClient).randomData(any(), sent.capture());
        assertEquals(2, sent.getValue().getLength());
        assertSame(request.getAttributes(), sent.getValue().getOperationAttributes());
        assertEquals(Base64.getEncoder().encodeToString(new byte[]{9, 8}), response.getData());
    }

    @Test
    void randomData_rejectsInvalidAttributes_beforeCallingConnector() throws Exception {
        // given
        List<BaseAttribute> definitions = List.of(new DataAttributeV2());
        when(operationsClient.listRandomAttributes(any(), any())).thenReturn(definitions);
        doThrow(new AttributeException("missing length-hint"))
                .when(attributeEngine)
                .validateUpdateDataAttributes(any(), any(), any(), any());
        RandomDataRequestDto request = new RandomDataRequestDto();
        request.setLength(2);
        request.setAttributes(List.of());

        // when
        Executable generate = () -> adapter.randomData(token, request);

        // then
        assertThrows(ValidationException.class, generate);
        verify(operationsClient, never()).randomData(any(), any());
    }

    private ImmutableTokenProfileBasicModel profile() {
        return new ImmutableTokenProfileBasicModel(UUID.randomUUID(), "profile", null, token.name(), token.uuid(), true,
                List.of(KeyUsage.SIGN, KeyUsage.VERIFY));
    }

    private void stubAttributes(Resource resource, UUID uuid, List<RequestAttribute> stored,
            List<RequestAttribute> resolved) throws ConnectorException {
        ObjectAttributeContentInfo scope = ObjectAttributeContentInfo
                .builder(resource, uuid)
                .connector(token.connectorUuid())
                .build();
        when(attributeEngine.getRequestObjectDataAttributesContent(scope)).thenReturn(stored);
        when(operationAttributeResolver.resolveForConnectorRequestAsSystem(token.connectorUuid(), stored))
                .thenReturn(resolved);
    }

    private static RequestAttribute requestAttribute(String name) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        return attribute;
    }

    private static ImmutableConnectorFullModel connector(UUID connectorUuid) {
        return new ImmutableConnectorFullModel(connectorUuid, "connector", ConnectorVersion.V2, "http://connector.test",
                null, List.of(), ConnectorStatus.CONNECTED, null, List.of(), List.of());
    }

    private static ImmutableTokenInstanceBasicModel token(UUID connectorUuid) {
        return new ImmutableTokenInstanceBasicModel(UUID.randomUUID(), null, "token", TokenInstanceStatus.UNKNOWN,
                "SOFT", connectorUuid, "connector", UUID.randomUUID(), ConnectorInterface.CRYPTOGRAPHY, "v2", 0);
    }
}
