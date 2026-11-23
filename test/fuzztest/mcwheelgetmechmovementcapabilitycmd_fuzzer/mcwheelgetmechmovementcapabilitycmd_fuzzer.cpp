/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mcwheelgetmechmovementcapabilitycmd_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <securec.h>
#include <vector>

#include "mc_wheel_get_mech_movement_capability_cmd.h"
#include "mc_data_buffer.h"

using namespace OHOS;
using namespace OHOS::MechBodyController;

namespace {
void FuzzMarshal(FuzzedDataProvider &provider)
{
    WheelGetMechMovementCapabilityCmd cmd;
    auto buffer = cmd.Marshal();
}

void FuzzSetCapability(FuzzedDataProvider &provider)
{
    WheelGetMechMovementCapabilityCmd cmd;
    uint32_t cap = provider.ConsumeIntegral<uint32_t>();
    cmd.SetCapability(cap);
}

void FuzzSetCapabilityBitValue(FuzzedDataProvider &provider)
{
    WheelGetMechMovementCapabilityCmd cmd;
    uint32_t start = provider.ConsumeIntegral<uint32_t>();
    uint8_t value = provider.ConsumeIntegral<uint8_t>();
    uint8_t index = provider.ConsumeIntegral<uint8_t>();
    cmd.SetCapabilityBitValue(start, value, index);
}

void FuzzOnDataReceive(FuzzedDataProvider &provider)
{
    WheelGetMechMovementCapabilityCmd cmd;

    size_t remaining = provider.remaining_bytes();
    if (remaining == 0) {
        return;
    }

    /* Construct a raw byte array for OnDataReceive.
     * OnDataReceive expects: segNum(1 byte) followed by
     * segments, each with: start(4 bytes), len(1 byte), then len bytes of data.
     * We use fuzz data directly as the raw buffer.
     */
    std::vector<uint8_t> rawData = provider.ConsumeBytes<uint8_t>(
        provider.ConsumeIntegralInRange<size_t>(1, remaining));
    if (rawData.empty()) {
        return;
    }

    cmd.OnDataReceive(rawData.data());
}

void FuzzOnDataReceiveSmallBuffer(FuzzedDataProvider &provider)
{
    WheelGetMechMovementCapabilityCmd cmd;

    /* Test with a very small buffer (just segNum byte) */
    uint8_t smallBuf[1] = {0};
    smallBuf[0] = provider.ConsumeIntegral<uint8_t>();
    cmd.OnDataReceive(smallBuf);
}

void FuzzOnDataReceiveValidStructure(FuzzedDataProvider &provider)
{
    WheelGetMechMovementCapabilityCmd cmd;

    /* Construct a well-structured buffer for OnDataReceive */
    uint8_t segNum = provider.ConsumeIntegralInRange<uint8_t>(0, 5);
    std::vector<uint8_t> buffer;
    buffer.push_back(segNum);

    for (uint8_t i = 0; i < segNum; i++) {
        uint32_t start = provider.ConsumeIntegral<uint32_t>();
        uint8_t len = provider.ConsumeIntegralInRange<uint8_t>(0, 5);

        /* Append start as 4 bytes */
        buffer.push_back(static_cast<uint8_t>(start & 0xFF));
        buffer.push_back(static_cast<uint8_t>((start >> 8) & 0xFF));
        buffer.push_back(static_cast<uint8_t>((start >> 16) & 0xFF));
        buffer.push_back(static_cast<uint8_t>((start >> 24) & 0xFF));

        /* Append len */
        buffer.push_back(len);

        /* Append len bytes of capability data */
        for (uint8_t j = 0; j < len; j++) {
            buffer.push_back(provider.ConsumeIntegral<uint8_t>());
        }
    }

    if (!buffer.empty()) {
        cmd.OnDataReceive(buffer.data());
    }
}

void FuzzOnDataReceiveInvalidSegNum(FuzzedDataProvider &provider)
{
    WheelGetMechMovementCapabilityCmd cmd;

    /* Test with segNum > 32 (should trigger early return) */
    uint8_t invalidSegBuf[2];
    invalidSegBuf[0] = 33; /* Invalid segNum > 32 */
    invalidSegBuf[1] = 0;
    cmd.OnDataReceive(invalidSegBuf);
}

void FuzzOnDataReceiveInvalidLen(FuzzedDataProvider &provider)
{
    WheelGetMechMovementCapabilityCmd cmd;

    /* Construct buffer with valid segNum but invalid len > 32 */
    uint8_t buf[6];
    buf[0] = 1; /* segNum = 1 */
    buf[1] = 0; /* start byte 0 */
    buf[2] = 0; /* start byte 1 */
    buf[3] = 0; /* start byte 2 */
    buf[4] = 0; /* start byte 3 */
    buf[5] = 33; /* len = 33 (invalid, > 32) */
    cmd.OnDataReceive(buf);
}

void FuzzTriggerResponse(FuzzedDataProvider &provider)
{
    WheelGetMechMovementCapabilityCmd cmd;

    /* RSP_SIZE = 20, BIT_OFFSET_2 = 2, so minimum data size = 22 */
    size_t dataSize = provider.ConsumeIntegralInRange<size_t>(1, 256);
    auto dataBuffer = std::make_shared<MechDataBuffer>(dataSize);
    if (dataBuffer == nullptr) {
        return;
    }

    /* Fill the buffer with fuzz data */
    for (size_t i = 0; i < dataSize; i++) {
        uint8_t byte = provider.ConsumeIntegral<uint8_t>();
        dataBuffer->AppendUint8(byte);
    }

    cmd.TriggerResponse(dataBuffer);
}

void FuzzTriggerResponseNullData(FuzzedDataProvider &provider)
{
    WheelGetMechMovementCapabilityCmd cmd;
    cmd.TriggerResponse(nullptr);
}

void FuzzTriggerResponseSmallData(FuzzedDataProvider &provider)
{
    WheelGetMechMovementCapabilityCmd cmd;

    /* Test with data smaller than RSP_SIZE + BIT_OFFSET_2 = 22 */
    size_t smallSize = provider.ConsumeIntegralInRange<size_t>(1, 21);
    auto dataBuffer = std::make_shared<MechDataBuffer>(smallSize);
    if (dataBuffer == nullptr) {
        return;
    }

    for (size_t i = 0; i < smallSize; i++) {
        dataBuffer->AppendUint8(provider.ConsumeIntegral<uint8_t>());
    }

    cmd.TriggerResponse(dataBuffer);
}

void FuzzTriggerResponseWithCallback(FuzzedDataProvider &provider)
{
    WheelGetMechMovementCapabilityCmd cmd;

    /* Set a response callback */
    bool callbackCalled = false;
    cmd.SetResponseCallback([&callbackCalled]() {
        callbackCalled = true;
    });

    /* Construct a valid-sized response buffer (RSP_SIZE + BIT_OFFSET_2 = 22) */
    size_t dataSize = 22;
    auto dataBuffer = std::make_shared<MechDataBuffer>(dataSize + 10);
    if (dataBuffer == nullptr) {
        return;
    }

    /* First 2 bytes are cmdSet and cmdId (BIT_OFFSET_2 = 2) */
    dataBuffer->AppendUint8(0x03); /* cmdSet */
    dataBuffer->AppendUint8(0x01); /* cmdId */
    /* result_ byte at offset 2 */
    dataBuffer->AppendUint8(provider.ConsumeIntegral<uint8_t>());
    /* OnDataReceive data starts at offset 3 */
    for (size_t i = 3; i < dataSize + 10; i++) {
        dataBuffer->AppendUint8(provider.ConsumeIntegral<uint8_t>());
    }

    cmd.TriggerResponse(dataBuffer);
}

void FuzzGetResult(FuzzedDataProvider &provider)
{
    WheelGetMechMovementCapabilityCmd cmd;
    /* GetResult returns result_ which defaults to 0 */
    uint8_t result = cmd.GetResult();
    (void)result;
}

void FuzzMarshalAndBasicOps(FuzzedDataProvider &provider)
{
    WheelGetMechMovementCapabilityCmd cmd;

    /* Test Marshal */
    auto buffer = cmd.Marshal();

    /* Test SetCapability with various values */
    uint32_t cap1 = provider.ConsumeIntegral<uint32_t>();
    cmd.SetCapability(cap1);

    /* Test SetCapabilityBitValue */
    uint32_t start = provider.ConsumeIntegral<uint32_t>();
    uint8_t value = provider.ConsumeIntegral<uint8_t>();
    uint8_t index = provider.ConsumeIntegral<uint8_t>();
    cmd.SetCapabilityBitValue(start, value, index);

    /* Test GetResult */
    cmd.GetResult();
}

void FuzzCommandBaseProperties(FuzzedDataProvider &provider)
{
    WheelGetMechMovementCapabilityCmd cmd;

    /* Access base class properties to verify constructor setup */
    (void)cmd.GetCmdSet();
    (void)cmd.GetCmdId();
    (void)cmd.GetReqSize();
    (void)cmd.GetRspSize();
    (void)cmd.NeedResponse();
    (void)cmd.GetTimeoutMs();
    (void)cmd.GetRetryTimes();
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return 0;
    }

    FuzzedDataProvider provider(data, size);

    FuzzMarshal(provider);
    FuzzSetCapability(provider);
    FuzzSetCapabilityBitValue(provider);
    FuzzOnDataReceive(provider);
    FuzzOnDataReceiveSmallBuffer(provider);
    FuzzOnDataReceiveValidStructure(provider);
    FuzzOnDataReceiveInvalidSegNum(provider);
    FuzzOnDataReceiveInvalidLen(provider);
    FuzzTriggerResponse(provider);
    FuzzTriggerResponseNullData(provider);
    FuzzTriggerResponseSmallData(provider);
    FuzzTriggerResponseWithCallback(provider);
    FuzzGetResult(provider);
    FuzzMarshalAndBasicOps(provider);
    FuzzCommandBaseProperties(provider);

    return 0;
}
