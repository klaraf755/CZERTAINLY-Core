package com.otilm.core.service.impl;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.cryptography.operations.CipherDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.enums.BitMaskEnum;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.cryptography.key.KeyEvent;
import com.otilm.api.model.core.cryptography.key.KeyEventStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.crypto.KeyOperationScope;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicKeyEventHistoryService;
import com.otilm.core.service.CryptographicKeyInternalService;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.handler.key.OperationKeyContext;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.function.Executable;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CryptographicOperationServiceImplTest {

    @Mock
    private CryptographicKeyInternalService keyService;
    @Mock
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Mock
    private KeyProviderAdapterFactory keyProviderAdapterFactory;
    @Mock
    private KeyProviderAdapter adapter;
    @Mock
    private AuthorizationEnforcer authorizationEnforcer;
    @Mock
    private CryptographicKeyEventHistoryService eventHistoryService;
    @InjectMocks
    private CryptographicOperationServiceImpl service;

    @Test
    void signData_routesLegacyItemToAdapter_andRecordsSuccess() throws Exception {
        // given
        CryptographicKeyItemOperationModel key = legacyKey();
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);
        when(keyProviderAdapterFactory.forKeyItem(key)).thenReturn(adapter);
        SignDataResponseDto expected = new SignDataResponseDto();
        when(adapter.signData(any(), any())).thenReturn(expected);

        // when
        SignDataResponseDto response = service
                .signData(SecuredParentUUID.fromUUID(key.tokenInstanceUuid()), SecuredUUID.fromUUID(UUID.randomUUID()),
                        UUID.randomUUID(), key.keyItemUuid(), signRequest());

        // then
        assertSame(expected, response);
        ArgumentCaptor<OperationKeyContext> context = ArgumentCaptor.forClass(OperationKeyContext.class);
        verify(adapter).signData(context.capture(), any());
        assertSame(key, context.getValue().keyItem());
        assertNull(context.getValue().tokenProfile());
        verify(eventHistoryService)
                .addEventHistory(KeyEvent.SIGN, KeyEventStatus.SUCCESS, "Signing data success ", null,
                        key.keyItemUuid());
        verifyNoInteractions(cryptographicKeyRepository);
    }

    @Test
    void signData_loadsProfileScope_forV2Item_andChecksPathAssociation() throws Exception {
        // given
        CryptographicKeyItemOperationModel key = v2Key();
        KeyOperationScope scope = scopeFor(key);
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);
        when(cryptographicKeyRepository.findOperationScopeByUuid(key.keyUuid())).thenReturn(Optional.of(scope));
        when(keyProviderAdapterFactory.forKeyItem(key)).thenReturn(adapter);
        when(adapter.signData(any(), any())).thenReturn(new SignDataResponseDto());

        // when
        service
                .signData(SecuredParentUUID.fromUUID(UUID.randomUUID()), SecuredUUID.fromUUID(scope.tokenProfileUuid()),
                        key.keyUuid(), key.keyItemUuid(), signRequest());

        // then
        ArgumentCaptor<OperationKeyContext> context = ArgumentCaptor.forClass(OperationKeyContext.class);
        verify(adapter).signData(context.capture(), any());
        assertEquals(scope.tokenProfileUuid(), context.getValue().tokenProfile().uuid());
    }

    @Test
    void signData_rejectsV2Item_whenPathProfileDiffers() throws Exception {
        // given
        CryptographicKeyItemOperationModel key = v2Key();
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);
        when(cryptographicKeyRepository.findOperationScopeByUuid(key.keyUuid())).thenReturn(Optional.of(scopeFor(key)));

        // when
        Executable sign = () -> service
                .signData(SecuredParentUUID.fromUUID(UUID.randomUUID()), SecuredUUID.fromUUID(UUID.randomUUID()),
                        key.keyUuid(), key.keyItemUuid(), signRequest());

        // then
        assertThrows(ValidationException.class, sign);
        verifyNoInteractions(keyProviderAdapterFactory, adapter);
    }

    @Test
    void signData_rejectsV2Item_whenPathKeyDiffers() throws Exception {
        // given
        CryptographicKeyItemOperationModel key = v2Key();
        KeyOperationScope scope = scopeFor(key);
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);
        when(cryptographicKeyRepository.findOperationScopeByUuid(key.keyUuid())).thenReturn(Optional.of(scope));

        // when
        Executable sign = () -> service
                .signData(SecuredParentUUID.fromUUID(UUID.randomUUID()), SecuredUUID.fromUUID(scope.tokenProfileUuid()),
                        UUID.randomUUID(), key.keyItemUuid(), signRequest());

        // then
        assertThrows(ValidationException.class, sign);
        verifyNoInteractions(keyProviderAdapterFactory, adapter);
    }

    @Test
    void signData_recordsFailure_andRethrows_whenAdapterFails() throws Exception {
        // given
        CryptographicKeyItemOperationModel key = legacyKey();
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);
        when(keyProviderAdapterFactory.forKeyItem(key)).thenReturn(adapter);
        ConnectorException failure = new ConnectorException("boom");
        when(adapter.signData(any(), any())).thenThrow(failure);

        // when
        Executable sign = () -> service
                .signData(SecuredParentUUID.fromUUID(key.tokenInstanceUuid()), SecuredUUID.fromUUID(UUID.randomUUID()),
                        UUID.randomUUID(), key.keyItemUuid(), signRequest());

        // then
        assertSame(failure, assertThrows(ConnectorException.class, sign));
        verify(eventHistoryService)
                .addEventHistory(KeyEvent.SIGN, KeyEventStatus.FAILED, "Signing of data failed ",
                        Map.of("exception", "boom"), key.keyItemUuid());
    }

    @Test
    void signDataWithoutEventHistory_recordsNothing() throws Exception {
        // given
        CryptographicKeyItemOperationModel key = legacyKey();
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);
        when(keyProviderAdapterFactory.forKeyItem(key)).thenReturn(adapter);
        when(adapter.signData(any(), any())).thenReturn(new SignDataResponseDto());

        // when
        service
                .signDataWithoutEventHistory(SecuredParentUUID.fromUUID(key.tokenInstanceUuid()),
                        SecuredUUID.fromUUID(UUID.randomUUID()), UUID.randomUUID(), key.keyItemUuid(), signRequest());

        // then
        verifyNoInteractions(eventHistoryService);
    }

    @Test
    void encryptData_rejectsKeyWithoutUsage_beforeRouting() throws Exception {
        // given
        CryptographicKeyItemOperationModel key = withUsage(legacyKey(), List.of(KeyUsage.DECRYPT));
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);
        CipherDataRequestDto request = new CipherDataRequestDto();
        request.setCipherData(List.of());

        // when
        Executable encrypt = () -> service
                .encryptData(SecuredParentUUID.fromUUID(key.tokenInstanceUuid()),
                        SecuredUUID.fromUUID(UUID.randomUUID()), UUID.randomUUID(), key.keyItemUuid(), request);

        // then
        ValidationException failure = assertThrows(ValidationException.class, encrypt);
        assertTrue(failure.getMessage().contains("does not support encryption"));
        verifyNoInteractions(keyProviderAdapterFactory);
    }

    @Test
    void verifyData_rejectsInactiveKey() throws Exception {
        // given
        CryptographicKeyItemOperationModel active = legacyKey();
        CryptographicKeyItemOperationModel key = new CryptographicKeyItemOperationModel(active.keyItemUuid(), true,
                active.keyAlgorithm(), KeyState.DEACTIVATED, active.keyType(), active.keyUsage(), null,
                active.reference(), active.connectorUuid(), active.tokenInstanceUuid(), active.keyUuid(), null, null);
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);
        VerifyDataRequestDto request = new VerifyDataRequestDto();
        request.setSignatures(List.of());

        // when
        Executable verifyCall = () -> service
                .verifyData(SecuredParentUUID.fromUUID(key.tokenInstanceUuid()),
                        SecuredUUID.fromUUID(UUID.randomUUID()), UUID.randomUUID(), key.keyItemUuid(), request);

        // then
        assertThrows(ValidationException.class, verifyCall);
        verifyNoInteractions(keyProviderAdapterFactory);
    }

    private static CryptographicKeyItemOperationModel legacyKey() {
        return new CryptographicKeyItemOperationModel(UUID.randomUUID(), true, KeyAlgorithm.RSA, KeyState.ACTIVE,
                KeyType.PRIVATE_KEY, List.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT, KeyUsage.SIGN, KeyUsage.VERIFY), null,
                new RemoteKeyReference.UuidReference(UUID.randomUUID()), UUID.randomUUID(), UUID.randomUUID(),
                UUID.randomUUID(), null, null);
    }

    private static CryptographicKeyItemOperationModel v2Key() {
        MetadataAttributeV3 handle = new MetadataAttributeV3();
        handle.setName("provider-key-handle");
        return new CryptographicKeyItemOperationModel(UUID.randomUUID(), true, KeyAlgorithm.RSA, KeyState.ACTIVE,
                KeyType.PRIVATE_KEY, List.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT, KeyUsage.SIGN, KeyUsage.VERIFY), null,
                new RemoteKeyReference.MetadataReference(List.of(handle)), UUID.randomUUID(), null, UUID.randomUUID(),
                ConnectorInterface.CRYPTOGRAPHY, "v2");
    }

    private static CryptographicKeyItemOperationModel withUsage(CryptographicKeyItemOperationModel key,
            List<KeyUsage> usage) {
        return new CryptographicKeyItemOperationModel(key.keyItemUuid(), key.enabled(), key.keyAlgorithm(),
                key.keyState(), key.keyType(), usage, key.pqcParameterSpecName(), key.reference(), key.connectorUuid(),
                key.tokenInstanceUuid(), key.keyUuid(), key.connectorInterfaceCode(), key.connectorInterfaceVersion());
    }

    private static KeyOperationScope scopeFor(CryptographicKeyItemOperationModel key) {
        return new KeyOperationScope(key.keyUuid(), UUID.randomUUID(), "profile", null, "token", UUID.randomUUID(),
                true, BitMaskEnum.convertSetToBitMask(EnumSet.of(KeyUsage.SIGN)), null, key.connectorUuid());
    }

    private static SignDataRequestDto signRequest() {
        SignDataRequestDto request = new SignDataRequestDto();
        request.setData(List.of());
        request.setSignatureAttributes(List.of());
        return request;
    }
}
