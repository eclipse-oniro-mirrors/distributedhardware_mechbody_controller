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

#include "mechbodycontrollerserviceseven_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>

#define private public
#define protected public
#include "mechbody_controller_service.h"
#undef private
#undef protected
#include "ipc_skeleton.h"
#include "securec.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "tokenid_kit.h"
#include "system_ability.h"

namespace OHOS {
using namespace OHOS::MechBodyController;

static bool g_isSystemApp = true;
bool Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(uint64_t tokenId)
{
    return g_isSystemApp;
}

int Security::AccessToken::AccessTokenKit::VerifyAccessToken(uint32_t tokenId, const std::string &permissionName)
{
    return Security::AccessToken::PermissionState::PERMISSION_GRANTED;
}

void SetUserOperationFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t opVal = fdp.ConsumeIntegral<int32_t>();
    std::shared_ptr<Operation> operation = std::make_shared<Operation>(static_cast<Operation>(opVal));
    std::string mac = fdp.ConsumeRandomLengthString();
    std::string param = fdp.ConsumeRandomLengthString();

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.SetUserOperation(operation, mac, param);
}

void SetUserOperationNullOpFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::shared_ptr<Operation> operation = nullptr;
    std::string mac = fdp.ConsumeRandomLengthString();
    std::string param = fdp.ConsumeRandomLengthString();

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.SetUserOperation(operation, mac, param);
}

void SetUserOperationJsonFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t opVal = fdp.ConsumeIntegral<int32_t>();
    std::shared_ptr<Operation> operation = std::make_shared<Operation>(static_cast<Operation>(opVal));
    std::string mac = fdp.ConsumeRandomLengthString();

    std::string deviceName = fdp.ConsumeRandomLengthString();
    std::string identifier = fdp.ConsumeRandomLengthString();
    std::string param = "{\"device_name\":\"" + deviceName + "\",\"identifier\":\"" + identifier + "\"}";

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.SetUserOperation(operation, mac, param);
}

void OnDeviceConnectedFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint32_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    bool isFirstConnect = fdp.ConsumeBool();
    uint32_t identifier = fdp.ConsumeIntegral<uint32_t>();

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.OnDeviceConnected(mechId, isFirstConnect, identifier);
}

void OnDeviceDisconnectedFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.OnDeviceDisconnected(mechId);
}

void SetTrackingEnabledFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    bool isEnabled = fdp.ConsumeBool();
    bool isCapsuleSet = fdp.ConsumeBool();

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.SetTrackingEnabled(isEnabled, isCapsuleSet);
}

void GetTrackingEnabledFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    bool isEnabled = false;
    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.GetTrackingEnabled(isEnabled);
}

void NotifyMechEventFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    uint8_t eventIdx = fdp.ConsumeIntegral<uint8_t>() % 5;
    MechEventType mechEventType = static_cast<MechEventType>(eventIdx);

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.NotifyMechEvent(mechId, mechEventType);
}

void RotateByDegreeFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    std::string cmdId = fdp.ConsumeRandomLengthString();
    auto rotateByDegreeParam = std::make_shared<RotateByDegreeParam>();
    if (rotateByDegreeParam != nullptr) {
        rotateByDegreeParam->degree.yaw = fdp.ConsumeFloatingPoint<float>();
        rotateByDegreeParam->degree.roll = fdp.ConsumeFloatingPoint<float>();
        rotateByDegreeParam->degree.pitch = fdp.ConsumeFloatingPoint<float>();
        rotateByDegreeParam->duration = fdp.ConsumeIntegral<int32_t>();
    }

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.RotateByDegree(mechId, cmdId, rotateByDegreeParam);
}

void RotateByDegreeNullParamFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    std::string cmdId = fdp.ConsumeRandomLengthString();
    std::shared_ptr<RotateByDegreeParam> rotateByDegreeParam = nullptr;

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.RotateByDegree(mechId, cmdId, rotateByDegreeParam);
}

void RotateToEulerAnglesFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    std::string cmdId = fdp.ConsumeRandomLengthString();
    auto rotateToEulerAnglesParam = std::make_shared<RotateToEulerAnglesParam>();
    if (rotateToEulerAnglesParam != nullptr) {
        rotateToEulerAnglesParam->angles.yaw = fdp.ConsumeFloatingPoint<float>();
        rotateToEulerAnglesParam->angles.roll = fdp.ConsumeFloatingPoint<float>();
        rotateToEulerAnglesParam->angles.pitch = fdp.ConsumeFloatingPoint<float>();
        rotateToEulerAnglesParam->duration = fdp.ConsumeIntegral<int32_t>();
    }

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.RotateToEulerAngles(mechId, cmdId, rotateToEulerAnglesParam);
}

void RotateBySpeedFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    std::string cmdId = fdp.ConsumeRandomLengthString();
    auto rotateBySpeedParam = std::make_shared<RotateBySpeedParam>();
    if (rotateBySpeedParam != nullptr) {
        rotateBySpeedParam->speed.yawSpeed = fdp.ConsumeFloatingPoint<float>();
        rotateBySpeedParam->speed.rollSpeed = fdp.ConsumeFloatingPoint<float>();
        rotateBySpeedParam->speed.pitchSpeed = fdp.ConsumeFloatingPoint<float>();
        rotateBySpeedParam->duration = fdp.ConsumeFloatingPoint<float>();
    }

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.RotateBySpeed(mechId, cmdId, rotateBySpeedParam);
}

void RotateBySpeedNullParamFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    std::string cmdId = fdp.ConsumeRandomLengthString();
    std::shared_ptr<RotateBySpeedParam> rotateBySpeedParam = nullptr;

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.RotateBySpeed(mechId, cmdId, rotateBySpeedParam);
}

void StopMovingFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    std::string cmdId = fdp.ConsumeRandomLengthString();

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.StopMoving(mechId, cmdId);
}

void SearchTargetFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string napiCmdId = fdp.ConsumeRandomLengthString();
    auto targetInfo = std::make_shared<TargetInfo>();
    auto searchParams = std::make_shared<SearchParams>();

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.SearchTarget(napiCmdId, targetInfo, searchParams);
}

void SearchTargetNullParamFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string napiCmdId = fdp.ConsumeRandomLengthString();

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.SearchTarget(napiCmdId, nullptr, nullptr);
}

void SubscribeCallbackFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    uint8_t eventIdx = fdp.ConsumeIntegral<uint8_t>() % 5;
    MechEventType mechEventType = static_cast<MechEventType>(eventIdx);
    sptr<IRemoteObject> callback;

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.SubscribeCallback(callback, mechEventType);
}

void UnSubscribeCallbackFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    uint8_t eventIdx = fdp.ConsumeIntegral<uint8_t>() % 5;
    MechEventType mechEventType = static_cast<MechEventType>(eventIdx);

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.UnSubscribeCallback(mechEventType);
}

void GetTrackingEnabledDeviceFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    bool isEnabled = false;
    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.GetTrackingEnabledDevice(isEnabled);
}

void ConnectDeviceFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string cmdId = fdp.ConsumeRandomLengthString();
    auto addrInfo = std::make_shared<AddressInfo>();
    if (addrInfo != nullptr) {
        addrInfo->address = fdp.ConsumeRandomLengthString();
        addrInfo->addressType = static_cast<AddressType>(fdp.ConsumeIntegral<int32_t>());
    }
    auto params = std::make_shared<ConnectParam>();
    if (params != nullptr) {
        params->deviceName = fdp.ConsumeRandomLengthString();
        params->identifier = fdp.ConsumeIntegral<uint32_t>();
        params->custdata = fdp.ConsumeRandomLengthString();
    }

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.ConnectDevice(cmdId, addrInfo, params);
}

void DisconnectDeviceFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string cmdId = fdp.ConsumeRandomLengthString();
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.DisconnectDevice(cmdId, mechId);
}

void NotifyOperationResultFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    uint32_t tokenId = fdp.ConsumeIntegral<uint32_t>();
    std::string cmdId = fdp.ConsumeRandomLengthString();
    uint8_t resultIdx = fdp.ConsumeIntegral<uint8_t>() % 7;
    ExecResult result = static_cast<ExecResult>(resultIdx);

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.NotifyOperationResult(tokenId, cmdId, result);
}

void NotifyConnectResultFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    uint32_t tokenId = fdp.ConsumeIntegral<uint32_t>();
    std::string cmdId = fdp.ConsumeRandomLengthString();
    uint8_t stateIdx = fdp.ConsumeIntegral<uint8_t>() % 3;
    AttachmentState state = static_cast<AttachmentState>(stateIdx - 1);
    MechInfo mechInfo;
    mechInfo.mechId = fdp.ConsumeIntegral<int32_t>();
    mechInfo.mechName = fdp.ConsumeRandomLengthString();

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.NotifyConnectResult(tokenId, cmdId, state, mechInfo);
}

void SetTrackingLayoutFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    uint8_t layoutIdx = fdp.ConsumeIntegral<uint8_t>() % 4;
    CameraTrackingLayout layout = static_cast<CameraTrackingLayout>(layoutIdx);

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.SetTrackingLayout(layout);
}

void GetTrackingLayoutFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    CameraTrackingLayout layout = CameraTrackingLayout::DEFAULT;
    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.GetTrackingLayout(layout);
}

void GetMaxRotationTimeFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    std::shared_ptr<TimeLimit> timeLimit = std::make_shared<TimeLimit>();

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.GetMaxRotationTime(mechId, timeLimit);
}

void GetMaxRotationSpeedFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    RotateSpeedLimit speedLimit;

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.GetMaxRotationSpeed(mechId, speedLimit);
}

void GetRotationAnglesFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    std::shared_ptr<EulerAngles> eulerAngles = std::make_shared<EulerAngles>();

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.GetRotationAngles(mechId, eulerAngles);
}

void GetRotationDegreeLimitsFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    RotateDegreeLimit rotationLimit;

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.GetRotationDegreeLimits(mechId, rotationLimit);
}

void GetRotationAxesStatusFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    RotationAxesStatus axesStatus;

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.GetRotationAxesStatus(mechId, axesStatus);
}

void OnRotationAxesStatusChangeFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    RotationAxesStatus axesStatus;
    axesStatus.yawEnabled = fdp.ConsumeBool();
    axesStatus.rollEnabled = fdp.ConsumeBool();
    axesStatus.pitchEnabled = fdp.ConsumeBool();
    axesStatus.yawLimited = static_cast<RotationAxisLimited>(fdp.ConsumeIntegral<uint32_t>() % 3);
    axesStatus.rollLimited = static_cast<RotationAxisLimited>(fdp.ConsumeIntegral<uint32_t>() % 3);
    axesStatus.pitchLimited = static_cast<RotationAxisLimited>(fdp.ConsumeIntegral<uint32_t>() % 3);

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.OnRotationAxesStatusChange(mechId, axesStatus);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return 0;
    }
    /* Use first byte to decide whether IsSystemAppByFullTokenID returns true or false */
    FuzzedDataProvider fdp(data, size);
    OHOS::g_isSystemApp = fdp.ConsumeBool();

    /* Use second byte to select which test function to dispatch */
    constexpr uint8_t ACTION_COUNT = 31;
    uint8_t action = fdp.ConsumeIntegral<uint8_t>() % ACTION_COUNT;
    const uint8_t *actionData = data + 2;
    size_t actionSize = (size >= 2) ? size - 2 : 0;

    switch (action) {
        case 0:
            OHOS::SetUserOperationFuzzTest(actionData, actionSize);
            break;
        case 1:
            OHOS::SetUserOperationNullOpFuzzTest(actionData, actionSize);
            break;
        case 2:
            OHOS::SetUserOperationJsonFuzzTest(actionData, actionSize);
            break;
        case 3:
            OHOS::OnDeviceConnectedFuzzTest(actionData, actionSize);
            break;
        case 4:
            OHOS::OnDeviceDisconnectedFuzzTest(actionData, actionSize);
            break;
        case 5:
            OHOS::SetTrackingEnabledFuzzTest(actionData, actionSize);
            break;
        case 6:
            OHOS::GetTrackingEnabledFuzzTest(actionData, actionSize);
            break;
        case 7:
            OHOS::NotifyMechEventFuzzTest(actionData, actionSize);
            break;
        case 8:
            OHOS::RotateByDegreeFuzzTest(actionData, actionSize);
            break;
        case 9:
            OHOS::RotateByDegreeNullParamFuzzTest(actionData, actionSize);
            break;
        case 10:
            OHOS::RotateToEulerAnglesFuzzTest(actionData, actionSize);
            break;
        case 11:
            OHOS::RotateBySpeedFuzzTest(actionData, actionSize);
            break;
        case 12:
            OHOS::RotateBySpeedNullParamFuzzTest(actionData, actionSize);
            break;
        case 13:
            OHOS::StopMovingFuzzTest(actionData, actionSize);
            break;
        case 14:
            OHOS::SearchTargetFuzzTest(actionData, actionSize);
            break;
        case 15:
            OHOS::SearchTargetNullParamFuzzTest(actionData, actionSize);
            break;
        case 16:
            OHOS::SubscribeCallbackFuzzTest(actionData, actionSize);
            break;
        case 17:
            OHOS::UnSubscribeCallbackFuzzTest(actionData, actionSize);
            break;
        case 18:
            OHOS::GetTrackingEnabledDeviceFuzzTest(actionData, actionSize);
            break;
        case 19:
            OHOS::ConnectDeviceFuzzTest(actionData, actionSize);
            break;
        case 20:
            OHOS::DisconnectDeviceFuzzTest(actionData, actionSize);
            break;
        case 21:
            OHOS::NotifyOperationResultFuzzTest(actionData, actionSize);
            break;
        case 22:
            OHOS::NotifyConnectResultFuzzTest(actionData, actionSize);
            break;
        case 23:
            OHOS::SetTrackingLayoutFuzzTest(actionData, actionSize);
            break;
        case 24:
            OHOS::GetTrackingLayoutFuzzTest(actionData, actionSize);
            break;
        case 25:
            OHOS::GetMaxRotationTimeFuzzTest(actionData, actionSize);
            break;
        case 26:
            OHOS::GetMaxRotationSpeedFuzzTest(actionData, actionSize);
            break;
        case 27:
            OHOS::GetRotationAnglesFuzzTest(actionData, actionSize);
            break;
        case 28:
            OHOS::GetRotationDegreeLimitsFuzzTest(actionData, actionSize);
            break;
        case 29:
            OHOS::GetRotationAxesStatusFuzzTest(actionData, actionSize);
            break;
        case 30:
            OHOS::OnRotationAxesStatusChangeFuzzTest(actionData, actionSize);
            break;
        default:
            break;
    }
    return 0;
}
