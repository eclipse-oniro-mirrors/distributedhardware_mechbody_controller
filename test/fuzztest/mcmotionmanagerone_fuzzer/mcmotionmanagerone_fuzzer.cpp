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
#include "mcmotionmanagerone_fuzzer.h"
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
#include "mechbody_controller_log.h"
#include "mock_transport_send_adapter.h"

namespace {
constexpr int32_t TEST_MECH_ID = 1;
constexpr int32_t MAX_ACTION_TYPE_VALUE = 2006;
}

using namespace OHOS;
using namespace OHOS::MechBodyController;

namespace {
const std::string TAG = "MotionManagerOneFuzz";

std::shared_ptr<MotionManager> g_motionManager = nullptr;
std::shared_ptr<MockTransportSendAdapter> g_mockAdapter = nullptr;

void InitMotionManager()
{
    if (g_motionManager == nullptr) {
        g_mockAdapter = std::make_shared<MockTransportSendAdapter>();
        g_motionManager = std::make_shared<MotionManager>(g_mockAdapter, TEST_MECH_ID, false, 0x00000000);
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

void FuzzMechTrackingStatusNotifyWithDisabled(const std::shared_ptr<MechEventListenerImpl> &listener,
                                              FuzzedDataProvider &provider)
{
    auto cmd = std::make_shared<RegisterMechTrackingEnableCmd>();
    auto responseData = std::make_shared<MechDataBuffer>(2);
    auto isEnabled = provider.ConsumeBool();
    if (responseData != nullptr) {
        responseData->AppendUint8(0x00);
        responseData->AppendUint8(0x00);
        responseData->AppendUint8(isEnabled);
        cmd->Unmarshal(responseData);
        listener->MechTrackingStatusNotify(cmd);
    }
}

void FuzzAttitudeNotify(const std::shared_ptr<MechEventListenerImpl> &listener, FuzzedDataProvider &provider)
{
    auto attitudeCmd = std::make_shared<RegisterMechPositionInfoCmd>();
    auto attitudeData = std::make_shared<MechDataBuffer>(12);
    if (attitudeData != nullptr) {
        attitudeData->AppendFloat(provider.ConsumeFloatingPoint<float>());
        attitudeData->AppendFloat(provider.ConsumeFloatingPoint<float>());
        attitudeData->AppendFloat(provider.ConsumeFloatingPoint<float>());
        attitudeCmd->Unmarshal(attitudeData);
        listener->MechAttitudeNotify(attitudeCmd);
    }
}

void FuzzButtonEventNotify(const std::shared_ptr<MechEventListenerImpl> &listener, FuzzedDataProvider &provider)
{
    auto buttonCmd = std::make_shared<RegisterMechCameraKeyEventCmd>();
    auto buttonData = std::make_shared<MechDataBuffer>(8);
    if (buttonData != nullptr) {
        buttonData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        buttonData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        buttonData->AppendInt16(provider.ConsumeIntegral<int16_t>());
        buttonData->AppendInt16(provider.ConsumeIntegral<int16_t>());
        buttonCmd->Unmarshal(buttonData);
        listener->MechButtonEventNotify(buttonCmd);
    }
}

void FuzzParamNotify(const std::shared_ptr<MechEventListenerImpl> &listener, FuzzedDataProvider &provider)
{
    auto paramCmd = std::make_shared<RegisterMechStateInfoCmd>();
    auto paramData = std::make_shared<MechDataBuffer>(5);
    if (paramData != nullptr) {
        paramData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        paramData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        paramData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        paramData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        paramData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        paramCmd->Unmarshal(paramData);
        listener->MechParamNotify(paramCmd);
    }
}

void FuzzGenericEventNotify(const std::shared_ptr<MechEventListenerImpl> &listener, FuzzedDataProvider &provider)
{
    auto genericCmd = std::make_shared<NormalRegisterMechGenericEventCmd>();
    auto genericData = std::make_shared<MechDataBuffer>(5);
    if (genericData != nullptr) {
        genericData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        genericData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        genericData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        genericData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        genericData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        genericCmd->Unmarshal(genericData);
        listener->MechGenericEventNotify(genericCmd);
    }
}

void FuzzCliffInfoNotify(const std::shared_ptr<MechEventListenerImpl> &listener, FuzzedDataProvider &provider)
{
    auto cliffCmd = std::make_shared<RegisterMechCliffInfoCmd>();
    auto cliffData = std::make_shared<MechDataBuffer>(1);
    if (cliffData != nullptr) {
        cliffData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        cliffCmd->Unmarshal(cliffData);
        listener->MechCliffInfoNotify(cliffCmd);
    }
}

void FuzzObstacleInfoNotify(const std::shared_ptr<MechEventListenerImpl> &listener, FuzzedDataProvider &provider)
{
    auto obstacleCmd = std::make_shared<RegisterMechObstacleInfoCmd>();
    auto obstacleData = std::make_shared<MechDataBuffer>(1);
    if (obstacleData != nullptr) {
        obstacleData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        obstacleCmd->Unmarshal(obstacleData);
        listener->MechObstacleInfoNotify(obstacleCmd);
    }
}

void FuzzExecutionResultNotify(const std::shared_ptr<MechEventListenerImpl> &listener, FuzzedDataProvider &provider)
{
    auto resultCmd = std::make_shared<RegisterMechControlResultCmd>();
    auto resultData = std::make_shared<MechDataBuffer>(3);
    if (resultData != nullptr) {
        resultData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        resultData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        resultData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        resultCmd->Unmarshal(resultData);
        listener->MechExecutionResultNotify(resultCmd);
    }
}

void FuzzWheelZoomNotify(const std::shared_ptr<MechEventListenerImpl> &listener, FuzzedDataProvider &provider)
{
    auto wheelCmd = std::make_shared<RegisterMechWheelDataCmd>();
    auto wheelData = std::make_shared<MechDataBuffer>(5);
    if (wheelData != nullptr) {
        wheelData->AppendUint32(provider.ConsumeIntegral<uint32_t>());
        wheelData->AppendInt16(provider.ConsumeIntegral<int16_t>());
        wheelData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        wheelCmd->Unmarshal(wheelData);
        listener->MechWheelZoomNotify(wheelCmd);
    }
}

void FuzzTrackingStatusNotify(const std::shared_ptr<MechEventListenerImpl> &listener, FuzzedDataProvider &provider)
{
    auto trackingCmd = std::make_shared<RegisterMechTrackingEnableCmd>();
    auto trackingData = std::make_shared<MechDataBuffer>(2);
    if (trackingData != nullptr) {
        trackingData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        trackingData->AppendUint8(provider.ConsumeIntegral<uint8_t>());
        trackingCmd->Unmarshal(trackingData);
        listener->MechTrackingStatusNotify(trackingCmd);
    }
}

void FuzzAllNotifyMethods(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    InitMotionManager();
    auto listener = std::make_shared<MechEventListenerImpl>(g_motionManager);
    FuzzMechTrackingStatusNotifyWithDisabled(listener, provider);
    FuzzAttitudeNotify(listener, provider);
    FuzzButtonEventNotify(listener, provider);
    FuzzParamNotify(listener, provider);
    FuzzGenericEventNotify(listener, provider);
    FuzzCliffInfoNotify(listener, provider);
    FuzzObstacleInfoNotify(listener, provider);
    FuzzExecutionResultNotify(listener, provider);
    FuzzWheelZoomNotify(listener, provider);
    FuzzTrackingStatusNotify(listener, provider);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzAllNotifyMethods(data, size);
    return 0;
}