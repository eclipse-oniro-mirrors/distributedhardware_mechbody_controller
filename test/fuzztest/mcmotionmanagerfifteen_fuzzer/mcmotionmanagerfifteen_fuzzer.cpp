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
#include "mcmotionmanagerfifteen_fuzzer.h"
#include "mc_motion_manager.h"
#include "mc_connect_manager.h"
#include "mechbody_controller_types.h"
#include "mechbody_controller_enums.h"
#include "mc_send_adapter.h"
#include "mc_command_factory.h"
#include "mc_register_mech_position_info_cmd.h"
#include "mc_register_mech_camera_key_event_cmd.h"
#include "mc_register_mech_state_info_cmd.h"
#include "mc_normal_register_mech_generic_event_cmd.h"
#include "mc_register_mech_cliff_info_cmd.h"
#include "mc_register_mech_obstacle_info_cmd.h"
#include "mc_register_mech_control_result_cmd.h"
#include "mc_register_mech_wheel_data_cmd.h"
#include "mc_register_mech_tracking_enable_cmd.h"
#include "mc_get_mech_protocol_ver_cmd.h"
#include "mc_normal_get_mech_base_info_cmd.h"
#include "mc_normal_get_mech_capability_info_cmd.h"
#include "mc_get_mech_limit_info_cmd.h"
#include "mc_normal_set_mech_protocol_ver_cmd.h"
#include "mc_data_buffer.h"
#include <memory>
#include <map>
#include "mock_transport_send_adapter.h"
#include "mechbody_controller_log.h"

namespace {
constexpr int32_t TEST_MECH_ID = 1;
constexpr int32_t MAX_ACTION_TYPE_VALUE = 2006;
}

using namespace OHOS;
using namespace OHOS::MechBodyController;

namespace {
const std::string TAG = "MotionManagerFifteenFuzz";

std::shared_ptr<MotionManager> g_motionManager = nullptr;
std::shared_ptr<MockTransportSendAdapter> g_mockAdapter = nullptr;

void InitMotionManager()
{
    if (g_motionManager == nullptr) {
        g_mockAdapter = std::make_shared<MockTransportSendAdapter>();
        g_motionManager = std::make_shared<MotionManager>(g_mockAdapter, TEST_MECH_ID, false, 0x00000000);

        MechInfo testMech;
        testMech.mechId = TEST_MECH_ID;
        testMech.mechType = MechType::PORTABLE_GIMBAL;
        testMech.mac = "AA:BB:CC:DD:EE:FF";
        testMech.state = AttachmentState::ATTACHED;
        testMech.deviceIdentifier = 0x00000000;
        MechConnectManager::GetInstance().AddMechInfo(testMech);
        MechConnectManager::GetInstance().NotifyMechState(TEST_MECH_ID, true);
    }
}

// Primary: MechExecutionResultNotify with fuzz data through Unmarshal
// This exercises the core business logic of parsing control result and
// looking up callbacks by taskId
void FuzzMechExecutionResultNotifyWithUnmarshal(FuzzedDataProvider &provider)
{
    InitMotionManager();

    auto cmd = std::make_shared<RegisterMechControlResultCmd>();

    // Construct a MechDataBuffer with fuzz data for Unmarshal
    // Unmarshal expects at least RPT_SIZE + BIT_OFFSET_2 bytes
    constexpr size_t minSize = RegisterMechControlResultCmd::RPT_SIZE + BIT_OFFSET_2;
    size_t bufferSize = provider.ConsumeIntegralInRange<size_t>(minSize, minSize + 64);
    std::shared_ptr<MechDataBuffer> dataBuffer = std::make_shared<MechDataBuffer>(bufferSize);
    if (dataBuffer == nullptr || dataBuffer->Data() == nullptr) {
        g_motionManager->MechExecutionResultNotify(cmd);
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

    // Unmarshal fuzz data into cmd fields (controlResult_, taskId_)
    bool unmarshalResult = cmd->Unmarshal(dataBuffer);
    (void)unmarshalResult;

    // Call MechExecutionResultNotify with fuzz-populated cmd
    // This exercises the callback lookup logic using the fuzz-derived taskId
    g_motionManager->MechExecutionResultNotify(cmd);

    // Verify parsed values
    (void)cmd->GetControlResult();
    (void)cmd->GetTaskId();
    (void)cmd->GetResult();
}

// Secondary: no-param getters with minimal fuzz data allocation
void FuzzProcessTrackingStatus(FuzzedDataProvider &provider)
{
    InitMotionManager();
    (void)provider.ConsumeBool(); // consume minimal fuzz data
    g_motionManager->ProcessTrackingStatus();
}

void FuzzGetMechRealName(FuzzedDataProvider &provider)
{
    InitMotionManager();
    (void)provider.ConsumeBool(); // consume minimal fuzz data
    g_motionManager->GetMechRealName();
}

void FuzzGetWheelCapabilityInfo(FuzzedDataProvider &provider)
{
    InitMotionManager();
    (void)provider.ConsumeBool(); // consume minimal fuzz data
    g_motionManager->GetWheelCapabilityInfo();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    FuzzMechExecutionResultNotifyWithUnmarshal(provider);
    FuzzProcessTrackingStatus(provider);
    FuzzGetMechRealName(provider);
    FuzzGetWheelCapabilityInfo(provider);
    return 0;
}