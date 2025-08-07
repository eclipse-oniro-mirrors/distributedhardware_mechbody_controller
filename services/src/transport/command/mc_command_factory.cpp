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

#include "mc_command_factory.h"
#include "mechbody_controller_enums.h"
#include "mechbody_controller_log.h"

namespace OHOS {
namespace MechBodyController {
namespace {
    const std::string TAG = "CommandFactory";
    constexpr uint8_t CREATE_FROM_DATA_MIN_SIZE = 2;
}

std::shared_ptr<GetMechCameraTrackingLayoutCmd> CommandFactory::CreateGetMechCameraTrackingLayoutCmd()
{
    return std::make_shared<GetMechCameraTrackingLayoutCmd>();
}

std::shared_ptr<GetMechCapabilityInfoCmd> CommandFactory::CreateGetMechCapabilityInfoCmd()
{
    return std::make_shared<GetMechCapabilityInfoCmd>();
}

std::shared_ptr<SetMechCameraInfoCmd> CommandFactory::CreateSetMechCameraInfoCmd(
    const CameraInfoParams& params)
{
    return std::make_shared<SetMechCameraInfoCmd>(params);
}

std::shared_ptr<SetMechCameraTrackingEnableCmd> CommandFactory::CreateSetMechCameraTrackingEnableCmd(
    MechTrackingStatus status)
{
    return std::make_shared<SetMechCameraTrackingEnableCmd>(status);
}

std::shared_ptr<SetMechCameraTrackingFrameCmd> CommandFactory::CreateSetMechCameraTrackingFrameCmd(
    const TrackingFrameParams& params)
{
    return std::make_shared<SetMechCameraTrackingFrameCmd>(params);
}

std::shared_ptr<SetMechCameraTrackingLayoutCmd> CommandFactory::CreateSetMechCameraTrackingLayoutCmd(
    const LayoutParams& params)
{
    return std::make_shared<SetMechCameraTrackingLayoutCmd>(params);
}

std::shared_ptr<SetMechConfigCmd> CommandFactory::CreateSetMechConfigCmd(
    uint8_t configVersion)
{
    return std::make_shared<SetMechConfigCmd>(configVersion);
}

std::shared_ptr<SetMechHidPreemptiveCmd> CommandFactory::CreateSetMechHidPreemptiveCmd(
    bool isPreemptive)
{
    return std::make_shared<SetMechHidPreemptiveCmd>(isPreemptive);
}

std::shared_ptr<SetMechRotationBySpeedCmd> CommandFactory::CreateSetMechRotationBySpeedCmd(
    const RotateBySpeedParam& params)
{
    return std::make_shared<SetMechRotationBySpeedCmd>(params);
}

std::shared_ptr<SetMechRotationCmd> CommandFactory::CreateSetMechRotationCmd(
    const RotateParam& params)
{
    return std::make_shared<SetMechRotationCmd>(params);
}

std::shared_ptr<SetMechRotationTraceCmd> CommandFactory::CreateSetMechRotationTraceCmd(
    const std::vector<RotateParam>& params)
{
    return std::make_shared<SetMechRotationTraceCmd>(params);
}

std::shared_ptr<SetMechStopCmd> CommandFactory::CreateSetMechStopCmd()
{
    return std::make_shared<SetMechStopCmd>();
}


std::shared_ptr<RegisterMechCameraKeyEventCmd> CommandFactory::CreateRegisterMechCameraKeyEventCmd()
{
    return std::make_shared<RegisterMechCameraKeyEventCmd>();
}

std::shared_ptr<RegisterMechControlResultCmd> CommandFactory::CreateRegisterMechControlResultCmd()
{
    return std::make_shared<RegisterMechControlResultCmd>();
}

std::shared_ptr<RegisterMechPositionInfoCmd> CommandFactory::CreateRegisterMechPositionInfoCmd()
{
    return std::make_shared<RegisterMechPositionInfoCmd>();
}

std::shared_ptr<RegisterMechStateInfoCmd> CommandFactory::CreateRegisterMechStateInfoCmd()
{
    return std::make_shared<RegisterMechStateInfoCmd>();
}

std::shared_ptr<RegisterMechWheelDataCmd> CommandFactory::CreateRegisterMechWheelDataCmd()
{
    return std::make_shared<RegisterMechWheelDataCmd>();
}

std::shared_ptr<RegisterMechTrackingEnableCmd> CommandFactory::CreateRegisterMechTrackingEnableCmd()
{
    return std::make_shared<RegisterMechTrackingEnableCmd>();
}

std::shared_ptr<CommandBase> CommandFactory::CreateFromData(std::shared_ptr<MechDataBuffer> data)
{
    if (data->Size() < CREATE_FROM_DATA_MIN_SIZE) {
        return nullptr;
    }

    uint8_t cmdType = 0;
    uint8_t cmdId = 0;
    CHECK_ERR_RETURN_VALUE(data->ReadUint8(0, cmdType), nullptr, "read cmdType");
    CHECK_ERR_RETURN_VALUE(data->ReadUint8(BIT_OFFSET_1, cmdId), nullptr, "read cmdId");

    uint16_t type = (static_cast<uint16_t>(cmdType) << BIT_OFFSET_8) | cmdId;
    HILOGD("CmdType 0x%{public}x", type);

    switch (type) {
        case CMD_TYPE_BUTTON_EVENT_NOTIFY:
            return CreateAndUnmarshal<RegisterMechCameraKeyEventCmd>(data);
        case CMD_TYPE_PARAM_NOTIFY:
            return CreateAndUnmarshal<RegisterMechStateInfoCmd>(data);
        case CMD_TYPE_ATTITUDE_NOTIFY:
            return CreateAndUnmarshal<RegisterMechPositionInfoCmd>(data);
        case CMD_TYPE_EXE_RESULT_NOTIFY:
            return CreateAndUnmarshal<RegisterMechControlResultCmd>(data);
        case CMD_TYPE_WHEEL_DATA_NOTIFY:
            return CreateAndUnmarshal<RegisterMechWheelDataCmd>(data);
        case CMD_TYPE_TRACKING_ENABLED_NOTIFY:
            return CreateAndUnmarshal<RegisterMechTrackingEnableCmd>(data);
        default:
            return nullptr;
    }
    return nullptr;
}
} // namespace MechBodyController
} // namespace OHOS
