package com.otilm.core.service.handler;

import com.otilm.api.model.connector.cryptography.operations.RandomDataResponseDto;

public final class LegacyOperationFixtures {

    private LegacyOperationFixtures() {
    }

    public static RandomDataResponseDto randomResponse(byte[] data) {
        RandomDataResponseDto response = new RandomDataResponseDto();
        response.setData(data);
        return response;
    }
}
