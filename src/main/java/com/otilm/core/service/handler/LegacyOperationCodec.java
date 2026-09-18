package com.otilm.core.service.handler;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.connector.cryptography.operations.RandomDataRequestDto;
import java.util.List;

/** Builds connector-side v1 operation requests; the only file that names those DTOs. */
public final class LegacyOperationCodec {

    private LegacyOperationCodec() {
    }

    public static RandomDataRequestDto randomRequest(int length, List<RequestAttribute> attributes) {
        RandomDataRequestDto request = new RandomDataRequestDto();
        request.setLength(length);
        request.setAttributes(attributes);
        return request;
    }
}
