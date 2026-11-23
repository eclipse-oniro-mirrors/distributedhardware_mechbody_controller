/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <securec.h>
#include <cstdint>

#include "mccommandbase_fuzzer.h"
#include "mc_command_base.h"
#include "mc_register_mech_control_result_cmd.h"
#include "mc_data_buffer.h"
#include "mechbody_controller_log.h"
#include "mechbody_controller_enums.h"

using namespace OHOS::MechBodyController;

namespace {
    const std::string TAG = "McCommandBaseFuzzTest";

    enum class TestFunctionId {
        FUZZ_COMMAND_BASE_UNMARSHAL = 0,
        FUZZ_COMMAND_BASE_GETTERS = 1,
        FUZZ_COMMAND_BASE_CALLBACKS = 2
    };
}

class MockCommandBase : public CommandBase {
public:
    MockCommandBase() = default;
    ~MockCommandBase() override = default;

    std::shared_ptr<MechDataBuffer> Marshal() const override
    {
        return nullptr;
    }

    void TriggerResponse(std::shared_ptr<MechDataBuffer> data) override {}

    void SetCmdSet(uint8_t cmdSet) { cmdSet_ = cmdSet; }
    void SetCmdId(uint8_t cmdId) { cmdId_ = cmdId; }
    void SetReqSize(uint16_t reqSize) { reqSize_ = reqSize; }
    void SetRspSize(uint16_t rspSize) { rspSize_ = rspSize; }
    void SetNeedResponse(bool needResponse) { needResponse_ = needResponse; }
    void SetTimeoutMs(uint32_t timeoutMs) { timeoutMs_ = timeoutMs; }
    void SetRetryTimes(int32_t retryTimes) { retryTimes_ = retryTimes; }
};

// Primary fuzz target: Unmarshal with fuzz-constructed MechDataBuffer
// RegisterMechControlResultCmd::Unmarshal reads controlResult and taskId from
// the buffer at BIT_OFFSET_2 and BIT_OFFSET_3, exercising parsing logic
static void TestCommandBaseUnmarshal(FuzzedDataProvider &provider)
{
    RegisterMechControlResultCmd cmd;

    // Construct a MechDataBuffer with variable-length fuzz data
    // Unmarshal expects at least RPT_SIZE + BIT_OFFSET_2 bytes
    constexpr size_t minSize = RegisterMechControlResultCmd::RPT_SIZE + BIT_OFFSET_2;
    size_t bufferSize = provider.ConsumeIntegralInRange<size_t>(minSize, minSize + 64);
    std::shared_ptr<MechDataBuffer> dataBuffer = std::make_shared<MechDataBuffer>(bufferSize);
    if (dataBuffer == nullptr || dataBuffer->Data() == nullptr) {
        return;
    }

    // Fill buffer with fuzz data to exercise Unmarshal parsing
    size_t dataLen = provider.ConsumeIntegralInRange<size_t>(0, bufferSize);
    std::vector<uint8_t> fuzzBytes = provider.ConsumeBytes<uint8_t>(dataLen);
    if (!fuzzBytes.empty()) {
        size_t copyLen = std::min(fuzzBytes.size(), bufferSize);
        if (memcpy_s(dataBuffer->Data(), bufferSize, fuzzBytes.data(), copyLen) == EOK) {
            dataBuffer->SetRange(0, copyLen);
        }
    }

    // Call Unmarshal - primary fuzz target with complex parsing logic
    bool unmarshalResult = cmd.Unmarshal(dataBuffer);
    (void)unmarshalResult;

    // Verify parsed results
    (void)cmd.GetControlResult();
    (void)cmd.GetTaskId();
    (void)cmd.GetResult();

    // Also test TriggerResponse with the same fuzz-constructed buffer
    cmd.TriggerResponse(dataBuffer);
}

// Secondary: simple getter/setter test with minimal fuzz data
static void TestCommandBaseGetters(FuzzedDataProvider &provider)
{
    MockCommandBase cmd;
    cmd.SetCmdSet(provider.ConsumeIntegral<uint8_t>());
    cmd.SetCmdId(provider.ConsumeIntegral<uint8_t>());
    cmd.SetNeedResponse(provider.ConsumeBool());

    cmd.GetCmdSet();
    cmd.GetCmdId();
    cmd.GetCmdType();
    cmd.NeedResponse();
}

// Secondary: callback test with minimal fuzz data
static void TestCommandBaseCallbacks(FuzzedDataProvider &provider)
{
    MockCommandBase cmd;

    bool shouldSetCallbacks = provider.ConsumeBool();
    if (shouldSetCallbacks) {
        cmd.SetResponseCallback([]() {});
        cmd.SetTimeoutCallback([]() {});
        cmd.SetTimeoutResetCallback([]() {});
    }

    cmd.TriggerTimeout();
    cmd.TriggerTimeoutReset();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < 1) {
        return 0;
    }

    FuzzedDataProvider provider(data, size);
    uint8_t testType = provider.ConsumeIntegral<uint8_t>() % 3;

    switch (static_cast<TestFunctionId>(testType)) {
        case TestFunctionId::FUZZ_COMMAND_BASE_UNMARSHAL:
            TestCommandBaseUnmarshal(provider);
            break;
        case TestFunctionId::FUZZ_COMMAND_BASE_GETTERS:
            TestCommandBaseGetters(provider);
            break;
        case TestFunctionId::FUZZ_COMMAND_BASE_CALLBACKS:
            TestCommandBaseCallbacks(provider);
            break;
        default:
            break;
    }

    return 0;
}