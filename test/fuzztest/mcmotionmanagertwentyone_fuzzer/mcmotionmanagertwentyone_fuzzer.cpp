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
#include "mcmotionmanagertwentyone_fuzzer.h"
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
constexpr size_t STATE_INFO_DATA_SIZE = 5;
constexpr uint8_t PHONE_STATE_ON = 0x01;
constexpr uint8_t INVALID_STATE_BYTE = 0xFF;
constexpr int32_t TEST_MECH_ID = 1;
constexpr int16_t MAX_NONZERO_DEGREE = 32767;
// Device error code values matching MapDeviceErrorCodeToExecResult switch cases
constexpr uint8_t ERR_SUCCESS = 0;
constexpr uint8_t ERR_PARA_ERROR = 1;
constexpr uint8_t ERR_EXE_ERROR = 2;
constexpr uint8_t ERR_LIMITED = 3;
constexpr uint8_t ERR_EXE_TIMEOUT = 4;
constexpr uint8_t ERR_EXE_INTERRUPTED = 5;
constexpr uint8_t ERR_CLIFF = 6;
constexpr uint8_t ERR_OBSTACLE = 7;
constexpr uint8_t ERR_OTHER = 100;
// MechMode values
constexpr uint8_t MECH_MODE_FOLLOW = 0;
constexpr uint8_t MECH_MODE_PITCH_FREE = 1;
constexpr uint8_t MECH_MODE_FPV = 2;
constexpr uint8_t MECH_MODE_ROLL = 3;
constexpr uint8_t MECH_MODE_FREE = 4;
}

using namespace OHOS;
using namespace OHOS::MechBodyController;

namespace {
const std::string TAG = "MotionManagerTwentyOneFuzz";

std::shared_ptr<MotionManager> g_motionManager = nullptr;
std::shared_ptr<MockTransportSendAdapter> g_mockAdapter = nullptr;

class TestMotionManager : public MotionManager {
public:
    TestMotionManager(const std::shared_ptr<TransportSendAdapter> sendAdapter, int32_t mechId, bool isFirstConnect,
        const uint32_t &deviceIdentifier)
        : MotionManager(sendAdapter, mechId, isFirstConnect, deviceIdentifier) {}

    ExecResult TestMapDeviceErrorCodeToExecResult(uint16_t cmdType, uint8_t deviceErrorCode)
    {
        return MapDeviceErrorCodeToExecResult(cmdType, deviceErrorCode);
    }
};

void InitMotionManager()
{
    if (g_motionManager == nullptr) {
        g_mockAdapter = std::make_shared<MockTransportSendAdapter>();
        g_motionManager = std::make_shared<TestMotionManager>(g_mockAdapter, TEST_MECH_ID, false, 0x00000000);
        g_motionManager->Init();
        g_motionManager->RegisterAbilityStateChangeListener();
        g_motionManager->UnRegisterAbilityStateChangeListener();
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

void FuzzMapDeviceErrorCodeToExecResult(FuzzedDataProvider &provider)
{
    InitMotionManager();
    auto testManager = std::static_pointer_cast<TestMotionManager>(g_motionManager);

    // Test all specific switch cases plus random values for comprehensive coverage
    uint16_t cmdType = provider.ConsumeIntegral<uint16_t>();

    // First test a specific error code from the known switch cases
    uint8_t specificError = provider.ConsumeIntegral<uint8_t>();
    testManager->TestMapDeviceErrorCodeToExecResult(cmdType, specificError);

    // Test each known error code branch explicitly with a fuzzed cmdType
    uint16_t cmdType2 = provider.ConsumeIntegral<uint16_t>();
    testManager->TestMapDeviceErrorCodeToExecResult(cmdType2, ERR_SUCCESS);
    testManager->TestMapDeviceErrorCodeToExecResult(cmdType2, ERR_PARA_ERROR);
    testManager->TestMapDeviceErrorCodeToExecResult(cmdType2, ERR_EXE_ERROR);
    testManager->TestMapDeviceErrorCodeToExecResult(cmdType2, ERR_LIMITED);
    testManager->TestMapDeviceErrorCodeToExecResult(cmdType2, ERR_EXE_TIMEOUT);
    testManager->TestMapDeviceErrorCodeToExecResult(cmdType2, ERR_EXE_INTERRUPTED);
    testManager->TestMapDeviceErrorCodeToExecResult(cmdType2, ERR_CLIFF);
    testManager->TestMapDeviceErrorCodeToExecResult(cmdType2, ERR_OBSTACLE);
    testManager->TestMapDeviceErrorCodeToExecResult(cmdType2, ERR_OTHER);

    // Test default case with values not matching any explicit case
    uint16_t cmdType3 = provider.ConsumeIntegral<uint16_t>();
    uint8_t defaultError1 = provider.ConsumeIntegralInRange<uint8_t>(8, 99);
    testManager->TestMapDeviceErrorCodeToExecResult(cmdType3, defaultError1);
    uint8_t defaultError2 = provider.ConsumeIntegralInRange<uint8_t>(101, 255);
    testManager->TestMapDeviceErrorCodeToExecResult(cmdType3, defaultError2);
}

void NotifyMechParamWithMode(const std::shared_ptr<MechEventListenerImpl> &listener,
    uint8_t mechMode, FuzzedDataProvider &provider)
{
    auto cmd = std::make_shared<RegisterMechStateInfoCmd>();
    auto data = std::make_shared<MechDataBuffer>(STATE_INFO_DATA_SIZE);
    if (data != nullptr) {
        data->AppendUint8(mechMode);
        data->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        data->AppendUint8(PHONE_STATE_ON);
        data->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        data->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        cmd->Unmarshal(data);
        listener->MechParamNotify(cmd);
    }
}

void NotifyMechGenericEvent(const std::shared_ptr<MechEventListenerImpl> &listener, uint8_t lowPower,
    uint8_t attached, uint8_t yawDisable, FuzzedDataProvider &provider)
{
    auto cmd = std::make_shared<NormalRegisterMechGenericEventCmd>();
    auto data = std::make_shared<MechDataBuffer>(STATE_INFO_DATA_SIZE);
    if (data != nullptr) {
        data->AppendUint8(lowPower);
        data->AppendUint8(attached);
        data->AppendUint8(yawDisable);
        data->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        data->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        cmd->Unmarshal(data);
        listener->MechGenericEventNotify(cmd);
    }
}

void FuzzMechParamNotify(FuzzedDataProvider &provider)
{
    InitMotionManager();
    auto listener = std::make_shared<MechEventListenerImpl>(g_motionManager);

    // Test each MechMode value to cover all switch cases in MechParamNotify
    NotifyMechParamWithMode(listener, MECH_MODE_FOLLOW, provider);
    NotifyMechParamWithMode(listener, MECH_MODE_PITCH_FREE, provider);
    NotifyMechParamWithMode(listener, MECH_MODE_FPV, provider);
    NotifyMechParamWithMode(listener, MECH_MODE_ROLL, provider);
    NotifyMechParamWithMode(listener, MECH_MODE_FREE, provider);

    // Random MechMode (covers default case in MechParamNotify switch)
    NotifyMechParamWithMode(listener, provider.ConsumeIntegral<uint8_t>(), provider);
}

void FuzzMechButtonEventNotify(FuzzedDataProvider &provider)
{
    InitMotionManager();
    auto listener = std::make_shared<MechEventListenerImpl>(g_motionManager);

    // Test various camera key event values to cover valid and invalid event paths
    // CameraKeyEvent values: 0-5, 9-13 are valid; others are invalid
    auto cmd = std::make_shared<RegisterMechCameraKeyEventCmd>();
    auto data = std::make_shared<MechDataBuffer>(8);
    if (data != nullptr) {
        data->AppendUint8(provider.ConsumeIntegral<uint8_t>());  // event type
        data->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        data->AppendInt16(provider.ConsumeIntegral<int16_t>());  // stickX
        data->AppendInt16(provider.ConsumeIntegral<int16_t>());  // stickY
        cmd->Unmarshal(data);
        listener->MechButtonEventNotify(cmd);
    }

    // Also test with specific known CameraKeyEvent values for coverage
    const uint8_t keyEventValues[] = {
        0,  // START_FILMING
        1,  // SWITCH_CAMERA
        2,  // ZOOM_IN
        3,  // ZOOM_OUT
        4,  // SWITCH_PHOTO_FILM
        5,  // SWITCH_TRACKING
        9,  // DIRECTION_UP
        10, // DIRECTION_DOWN
        11, // DIRECTION_LEFT
        12, // DIRECTION_RIGHT
        13, // DIRECTION_CONFIRM
    };

    uint8_t eventIdx = provider.ConsumeIntegralInRange<uint8_t>(0, sizeof(keyEventValues) - 1);
    auto specificCmd = std::make_shared<RegisterMechCameraKeyEventCmd>();
    auto specificData = std::make_shared<MechDataBuffer>(8);
    if (specificData != nullptr) {
        specificData->AppendUint8(keyEventValues[eventIdx]);
        specificData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        specificData->AppendInt16(provider.ConsumeIntegral<int16_t>());
        specificData->AppendInt16(provider.ConsumeIntegral<int16_t>());
        specificCmd->Unmarshal(specificData);
        listener->MechButtonEventNotify(specificCmd);
    }
}

void FuzzMechGenericEventNotify(FuzzedDataProvider &provider)
{
    InitMotionManager();
    auto listener = std::make_shared<MechEventListenerImpl>(g_motionManager);

    // Test with random fuzz data
    NotifyMechGenericEvent(listener, provider.ConsumeIntegral<uint8_t>(),
        provider.ConsumeIntegral<uint8_t>(), provider.ConsumeIntegral<uint8_t>(), provider);

    // Test low power event path (lowPower == BIT_1)
    NotifyMechGenericEvent(listener, PHONE_STATE_ON, provider.ConsumeIntegral<uint8_t>(),
        provider.ConsumeIntegral<uint8_t>(), provider);

    // Test attached != -1 path
    NotifyMechGenericEvent(listener, provider.ConsumeIntegral<uint8_t>(), PHONE_STATE_ON, 0x00, provider);

    // Test early return when yawDisable == 0xFF (-1)
    NotifyMechGenericEvent(listener, provider.ConsumeIntegral<uint8_t>(), INVALID_STATE_BYTE,
        INVALID_STATE_BYTE, provider);
}

void FuzzMechExecutionResultNotify(FuzzedDataProvider &provider)
{
    InitMotionManager();
    auto listener = std::make_shared<MechEventListenerImpl>(g_motionManager);

    // Test with fuzz data for control result and task id
    auto cmd = std::make_shared<RegisterMechControlResultCmd>();
    auto data = std::make_shared<MechDataBuffer>(3);
    if (data != nullptr) {
        data->AppendUint8(provider.ConsumeIntegral<uint8_t>());  // control result low byte
        data->AppendUint8(provider.ConsumeIntegral<uint8_t>());  // control result high byte / taskId
        data->AppendUint8(provider.ConsumeIntegral<uint8_t>());  // result code
        cmd->Unmarshal(data);
        listener->MechExecutionResultNotify(cmd);
    }

    // Test with task completed result (value 2) to cover the completion path
    {
        auto completedCmd = std::make_shared<RegisterMechControlResultCmd>();
        auto completedData = std::make_shared<MechDataBuffer>(3);
        if (completedData != nullptr) {
            completedData->AppendUint8(0x02);  // TASK_COMPLETED low byte
            completedData->AppendUint8(0x00);
            completedData->AppendUint8(0x00);
            completedCmd->Unmarshal(completedData);
            listener->MechExecutionResultNotify(completedCmd);
        }
    }
}

void FuzzMechWheelZoomNotify(FuzzedDataProvider &provider)
{
    InitMotionManager();
    auto listener = std::make_shared<MechEventListenerImpl>(g_motionManager);

    // Test with random wheel data
    auto cmd = std::make_shared<RegisterMechWheelDataCmd>();
    auto data = std::make_shared<MechDataBuffer>(5);
    if (data != nullptr) {
        data->AppendUint32(provider.ConsumeIntegral<uint32_t>());  // wheel data header
        data->AppendInt16(provider.ConsumeIntegral<int16_t>());    // degree
        data->AppendUint8(provider.ConsumeIntegral<uint8_t>());    // speed_ratio
        cmd->Unmarshal(data);
        listener->MechWheelZoomNotify(cmd);
    }

    // Test with non-zero degree to cover the degree != 0 path
    {
        auto nonzeroCmd = std::make_shared<RegisterMechWheelDataCmd>();
        auto nonzeroData = std::make_shared<MechDataBuffer>(5);
        if (nonzeroData != nullptr) {
            nonzeroData->AppendUint32(provider.ConsumeIntegral<uint32_t>());
            nonzeroData->AppendInt16(
                provider.ConsumeIntegralInRange<int16_t>(1, MAX_NONZERO_DEGREE));  // non-zero degree
            nonzeroData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
            nonzeroCmd->Unmarshal(nonzeroData);
            listener->MechWheelZoomNotify(nonzeroCmd);
        }
    }

    // Test with zero degree to cover the early return path
    {
        auto zeroCmd = std::make_shared<RegisterMechWheelDataCmd>();
        auto zeroData = std::make_shared<MechDataBuffer>(5);
        if (zeroData != nullptr) {
            zeroData->AppendUint32(provider.ConsumeIntegral<uint32_t>());
            zeroData->AppendInt16(0);  // zero degree
            zeroData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
            zeroCmd->Unmarshal(zeroData);
            listener->MechWheelZoomNotify(zeroCmd);
        }
    }
}

void FuzzMechTrackingStatusNotify(FuzzedDataProvider &provider)
{
    InitMotionManager();
    auto listener = std::make_shared<MechEventListenerImpl>(g_motionManager);

    // Test with random tracking enable data
    auto cmd = std::make_shared<RegisterMechTrackingEnableCmd>();
    auto data = std::make_shared<MechDataBuffer>(2);
    if (data != nullptr) {
        data->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        data->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        cmd->Unmarshal(data);
        listener->MechTrackingStatusNotify(cmd);
    }

    // Test with tracking disabled (0x00)
    {
        auto disabledCmd = std::make_shared<RegisterMechTrackingEnableCmd>();
        auto disabledData = std::make_shared<MechDataBuffer>(2);
        if (disabledData != nullptr) {
            disabledData->AppendUint8(0x00);
            disabledData->AppendUint8(0x00);  // isEnabled = false
            disabledCmd->Unmarshal(disabledData);
            listener->MechTrackingStatusNotify(disabledCmd);
        }
    }

    // Test with tracking enabled (0x01)
    {
        auto enabledCmd = std::make_shared<RegisterMechTrackingEnableCmd>();
        auto enabledData = std::make_shared<MechDataBuffer>(2);
        if (enabledData != nullptr) {
            enabledData->AppendUint8(0x00);
            enabledData->AppendUint8(0x01);  // isEnabled = true
            enabledCmd->Unmarshal(enabledData);
            listener->MechTrackingStatusNotify(enabledCmd);
        }
    }
}

void FuzzMechAttitudeNotify(FuzzedDataProvider &provider)
{
    InitMotionManager();
    auto listener = std::make_shared<MechEventListenerImpl>(g_motionManager);

    // Test attitude notify with fuzz data to cover the position update path
    auto cmd = std::make_shared<RegisterMechPositionInfoCmd>();
    auto data = std::make_shared<MechDataBuffer>(12);
    if (data != nullptr) {
        data->AppendFloat(provider.ConsumeFloatingPoint<float>());  // yaw
        data->AppendFloat(provider.ConsumeFloatingPoint<float>());  // roll
        data->AppendFloat(provider.ConsumeFloatingPoint<float>());  // pitch
        cmd->Unmarshal(data);
        listener->MechAttitudeNotify(cmd);
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    FuzzMapDeviceErrorCodeToExecResult(provider);
    FuzzMechParamNotify(provider);
    FuzzMechButtonEventNotify(provider);
    FuzzMechGenericEventNotify(provider);
    FuzzMechExecutionResultNotify(provider);
    FuzzMechWheelZoomNotify(provider);
    FuzzMechTrackingStatusNotify(provider);
    FuzzMechAttitudeNotify(provider);
    return 0;
}
