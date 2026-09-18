package com.otilm.core.service.handler;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

class LegacyOperationCodecTest {

    @Test
    void randomRequest_copiesLengthAndAttributes() {
        // given
        List<RequestAttribute> attributes = List.of(new RequestAttributeV2());

        // when
        var request = LegacyOperationCodec.randomRequest(16, attributes);

        // then
        assertEquals(16, request.getLength());
        assertSame(attributes, request.getAttributes());
    }
}
