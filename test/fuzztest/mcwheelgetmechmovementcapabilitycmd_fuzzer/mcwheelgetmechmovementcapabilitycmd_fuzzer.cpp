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
 * See the License for the language governing permissions and
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
#include "mechbody_controller_types.h"

using namespace OHOS;
using namespace OHOS::MechBodyController;

namespace {
constexpr uint32_t MAX_CAPABILITY_BIT = 2006;

void FuzzSetCapability(FuzzedDataProvider &fdp)
{
    WheelGetMechMovementCapabilityCmd cmd;
    uint32_t cap = fdp.ConsumeIntegralInRange<uint32_t>(0, MAX_CAPABILITY_BIT - 1);
    cmd.SetCapability(cap);
}

void FuzzSetCapabilityBitValue(FuzzedDataProvider &fdp)
{
    WheelGetMechMovementCapabilityCmd cmd;
    uint8_t value = fdp.ConsumeIntegral<uint8_t>();
    uint8_t index = fdp.ConsumeIntegral<uint8_t>();
    uint32_t maxStart = (MAX_CAPABILITY_BIT > static_cast<uint32_t>(index) * 8 + 7)
        ? (MAX_CAPABILITY_BIT - static_cast<uint32_t>(index) * 8 - 8) : 0;
    uint32_t start = fdp.ConsumeIntegralInRange<uint32_t>(0, maxStart);
    cmd.SetCapabilityBitValue(start, value, index);
}

void FuzzOnDataReceive(FuzzedDataProvider &fdp)
{
    WheelGetMechMovementCapabilityCmd cmd;

    size_t remaining = fdp.remaining_bytes();
    if (remaining == 0) {
        return;
    }

    /* Construct a raw byte array for OnDataReceive.
     * OnDataReceive expects: segNum(1 byte) followed by
     * segments, each with: start(4 bytes), len(1 byte), then len bytes of data.
     * We use fuzz data directly as the raw buffer.
     */
    std::vector<uint8_t> rawData = fdp.ConsumeBytes<uint8_t>(
        fdp.ConsumeIntegralInRange<size_t>(1, remaining));
    if (rawData.empty()) {
        return;
    }

    cmd.OnDataReceive(rawData.data());
}

void FuzzOnDataReceiveValidStructure(FuzzedDataProvider &fdp)
{
    WheelGetMechMovementCapabilityCmd cmd;

    /* Construct a well-structured buffer for OnDataReceive */
    uint8_t segNum = fdp.ConsumeIntegralInRange<uint8_t>(0, 5);
    std::vector<uint8_t> buffer;
    buffer.push_back(segNum);

    for (uint8_t i = 0; i < segNum; i++) {
        uint32_t start = fdp.ConsumeIntegralInRange<uint32_t>(0, MAX_CAPABILITY_BIT - 1);
        uint8_t len = fdp.ConsumeIntegralInRange<uint8_t>(0, 5);

        /* Append start as 4 bytes */
        buffer.push_back(static_cast<uint8_t>(start & 0xFF));
        buffer.push_back(static_cast<uint8_t>((start >> 8) & 0xFF));
        buffer.push_back(static_cast<uint8_t>((start >> 16) & 0xFF));
        buffer.push_back(static_cast<uint8_t>((start >> 24) & 0xFF));

        /* Append len */
        buffer.push_back(len);

        /* Append len bytes of capability data */
        for (uint8_t j = 0; j < len; j++) {
            buffer.push_back(fdp.ConsumeIntegral<uint8_t>());
        }
    }

    if (!buffer.empty()) {
        cmd.OnDataReceive(buffer.data());
    }
}

void FuzzOnDataReceiveInvalidSegNum(FuzzedDataProvider &fdp)
{
    WheelGetMechMovementCapabilityCmd cmd;

    /* Use fuzz data to construct an invalid segNum (> 32) to trigger early return */
    uint8_t invalidSegNum = fdp.ConsumeIntegralInRange<uint8_t>(33, 255);
    uint8_t buf[2];
    buf[0] = invalidSegNum;
    buf[1] = fdp.ConsumeIntegral<uint8_t>();
    cmd.OnDataReceive(buf);
}

void FuzzOnDataReceiveInvalidLen(FuzzedDataProvider &fdp)
{
    WheelGetMechMovementCapabilityCmd cmd;

    /* Construct buffer with valid segNum but invalid len > 32 */
    uint8_t buf[6];
    buf[0] = 1; /* segNum = 1 */
    uint32_t start = fdp.ConsumeIntegralInRange<uint32_t>(0, MAX_CAPABILITY_BIT - 1);
    buf[1] = static_cast<uint8_t>(start & 0xFF);
    buf[2] = static_cast<uint8_t>((start >> 8) & 0xFF);
    buf[3] = static_cast<uint8_t>((start >> 16) & 0xFF);
    buf[4] = static_cast<uint8_t>((start >> 24) & 0xFF);
    buf[5] = fdp.ConsumeIntegralInRange<uint8_t>(33, 255); /* Invalid len > 32 */
    cmd.OnDataReceive(buf);
}

void FuzzTriggerResponse(FuzzedDataProvider &fdp)
{
    WheelGetMechMovementCapabilityCmd cmd;

    /* RSP_SIZE = 20, BIT_OFFSET_2 = 2, so minimum data size = 22 */
    size_t dataSize = fdp.ConsumeIntegralInRange<size_t>(1, 256);
    auto dataBuffer = std::make_shared<MechDataBuffer>(dataSize);
    if (dataBuffer == nullptr) {
        return;
    }

    /* Fill the buffer with fuzz data */
    for (size_t i = 0; i < dataSize; i++) {
        uint8_t byte = fdp.ConsumeIntegral<uint8_t>();
        dataBuffer->AppendUint8(byte);
    }

    cmd.TriggerResponse(dataBuffer);
}

void FuzzTriggerResponseWithCallback(FuzzedDataProvider &fdp)
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
    dataBuffer->AppendUint8(fdp.ConsumeIntegral<uint8_t>());
    /* OnDataReceive data starts at offset 3 */
    for (size_t i = 3; i < dataSize + 10; i++) {
        dataBuffer->AppendUint8(fdp.ConsumeIntegral<uint8_t>());
    }

    cmd.TriggerResponse(dataBuffer);
}

void FuzzMarshalAndBasicOps(FuzzedDataProvider &fdp)
{
    WheelGetMechMovementCapabilityCmd cmd;

    /* Test Marshal */
    auto buffer = cmd.Marshal();

    /* Test SetCapability with various values */
    uint32_t cap1 = fdp.ConsumeIntegralInRange<uint32_t>(0, MAX_CAPABILITY_BIT - 1);
    cmd.SetCapability(cap1);

    /* Test SetCapabilityBitValue */
    uint8_t value = fdp.ConsumeIntegral<uint8_t>();
    uint8_t index = fdp.ConsumeIntegral<uint8_t>();
    uint32_t maxStart = (MAX_CAPABILITY_BIT > static_cast<uint32_t>(index) * 8 + 7)
        ? (MAX_CAPABILITY_BIT - static_cast<uint32_t>(index) * 8 - 8) : 0;
    uint32_t start = fdp.ConsumeIntegralInRange<uint32_t>(0, maxStart);
    cmd.SetCapabilityBitValue(start, value, index);

    /* Test GetResult */
    cmd.GetResult();
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    uint8_t funcIndex = fdp.ConsumeIntegral<uint8_t>() % 9;
    switch (funcIndex) {
        case 0:
            FuzzSetCapability(fdp);
            break;
        case 1:
            FuzzSetCapabilityBitValue(fdp);
            break;
        case 2:
            FuzzOnDataReceive(fdp);
            break;
        case 3:
            FuzzOnDataReceiveValidStructure(fdp);
            break;
        case 4:
            FuzzOnDataReceiveInvalidSegNum(fdp);
            break;
        case 5:
            FuzzOnDataReceiveInvalidLen(fdp);
            break;
        case 6:
            FuzzTriggerResponse(fdp);
            break;
        case 7:
            FuzzTriggerResponseWithCallback(fdp);
            break;
        case 8:
            FuzzMarshalAndBasicOps(fdp);
            break;
        default:
            break;
    }
    return 0;
}
