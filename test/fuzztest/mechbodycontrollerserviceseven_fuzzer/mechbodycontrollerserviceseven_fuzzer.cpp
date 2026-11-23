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
#include "ipc_object_stub.h"
#include "securec.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "tokenid_kit.h"
#include "system_ability.h"

namespace OHOS {
using namespace OHOS::MechBodyController;
namespace {
constexpr uint8_t MECH_EVENT_TYPE_COUNT = 5;
constexpr uint8_t ADDRESS_TYPE_COUNT = 3;
constexpr uint8_t EXEC_RESULT_COUNT = 7;
constexpr uint8_t TRACKING_LAYOUT_COUNT = 4;
constexpr uint8_t ROTATION_AXIS_LIMITED_COUNT = 3;
constexpr int32_t MIN_ATTACHMENT_STATE = static_cast<int32_t>(AttachmentState::UNKNOWN);
constexpr int32_t MAX_ATTACHMENT_STATE = static_cast<int32_t>(AttachmentState::DETACHED);
constexpr uint32_t MIN_QUERY_COUNT = 1;
constexpr uint32_t MAX_QUERY_COUNT = 3;
} // namespace

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

void NotifyMechEventFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    uint8_t eventIdx = fdp.ConsumeIntegral<uint8_t>() % MECH_EVENT_TYPE_COUNT;
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
    uint8_t eventIdx = fdp.ConsumeIntegral<uint8_t>() % MECH_EVENT_TYPE_COUNT;
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
    uint8_t eventIdx = fdp.ConsumeIntegral<uint8_t>() % MECH_EVENT_TYPE_COUNT;
    MechEventType mechEventType = static_cast<MechEventType>(eventIdx);

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.UnSubscribeCallback(mechEventType);
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
        addrInfo->addressType = static_cast<AddressType>(fdp.ConsumeIntegral<uint8_t>() % ADDRESS_TYPE_COUNT);
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
    uint8_t resultIdx = fdp.ConsumeIntegral<uint8_t>() % EXEC_RESULT_COUNT;
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
    int32_t stateIdx = fdp.ConsumeIntegralInRange<int32_t>(MIN_ATTACHMENT_STATE, MAX_ATTACHMENT_STATE);
    AttachmentState state = static_cast<AttachmentState>(stateIdx);
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
    uint8_t layoutIdx = fdp.ConsumeIntegral<uint8_t>() % TRACKING_LAYOUT_COUNT;
    CameraTrackingLayout layout = static_cast<CameraTrackingLayout>(layoutIdx);

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.SetTrackingLayout(layout);
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
    axesStatus.yawLimited = static_cast<RotationAxisLimited>(
        fdp.ConsumeIntegral<uint32_t>() % ROTATION_AXIS_LIMITED_COUNT);
    axesStatus.rollLimited = static_cast<RotationAxisLimited>(
        fdp.ConsumeIntegral<uint32_t>() % ROTATION_AXIS_LIMITED_COUNT);
    axesStatus.pitchLimited = static_cast<RotationAxisLimited>(
        fdp.ConsumeIntegral<uint32_t>() % ROTATION_AXIS_LIMITED_COUNT);

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.OnRotationAxesStatusChange(mechId, axesStatus);
}

void RegisterAttachStateChangeCallbackFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    bool useCallback = fdp.ConsumeBool();
    sptr<IRemoteObject> callback = useCallback
        ? new IPCObjectStub(u"test.callback") : nullptr;

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.RegisterAttachStateChangeCallback(callback);
}

void RegisterTrackingEventCallbackFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    bool useCallback = fdp.ConsumeBool();
    sptr<IRemoteObject> callback = useCallback
        ? new IPCObjectStub(u"test.callback") : nullptr;

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.RegisterTrackingEventCallback(callback);
}

void UnRegisterTrackingEventCallbackFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    bool shouldRegisterFirst = fdp.ConsumeBool();
    bool useCallback = fdp.ConsumeBool();
    sptr<IRemoteObject> callback = useCallback
        ? new IPCObjectStub(u"test.callback") : nullptr;

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    if (shouldRegisterFirst) {
        service.RegisterTrackingEventCallback(callback);
    }
    service.UnRegisterTrackingEventCallback();
}

void RegisterCmdChannelFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    bool useCallback = fdp.ConsumeBool();
    sptr<IRemoteObject> callback = useCallback
        ? new IPCObjectStub(u"test.callback") : nullptr;

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.RegisterCmdChannel(callback);
}

void RegisterRotationAxesStatusChangeCallbackFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    bool useCallback = fdp.ConsumeBool();
    sptr<IRemoteObject> callback = useCallback
        ? new IPCObjectStub(u"test.callback") : nullptr;

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.RegisterRotationAxesStatusChangeCallback(callback);
}

void UnRegisterRotationAxesStatusChangeCallbackFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    bool isSystemApp = fdp.ConsumeBool();
    bool shouldRegisterFirst = fdp.ConsumeBool();
    bool useCallback = fdp.ConsumeBool();
    sptr<IRemoteObject> callback = useCallback
        ? new IPCObjectStub(u"test.callback") : nullptr;

    OHOS::g_isSystemApp = isSystemApp;
    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    if (shouldRegisterFirst) {
        service.RegisterRotationAxesStatusChangeCallback(callback);
    }
    service.UnRegisterRotationAxesStatusChangeCallback();
}

void GetDeviceAdsorbStateFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    AttachmentState state = static_cast<AttachmentState>(
        fdp.ConsumeIntegralInRange<int32_t>(MIN_ATTACHMENT_STATE, MAX_ATTACHMENT_STATE));

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.GetDeviceAdsorbState(mechId, state);
}

void RegisterBatteryLevelCallbackFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    bool useCallback = fdp.ConsumeBool();
    sptr<IRemoteObject> callback = useCallback
        ? new IPCObjectStub(u"test.callback") : nullptr;
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.RegisterBatteryLevelCallback(callback, mechId);
}

void UnRegisterBatteryLevelCallbackFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    bool shouldRegisterFirst = fdp.ConsumeBool();
    bool useCallback = fdp.ConsumeBool();
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    sptr<IRemoteObject> callback = useCallback
        ? new IPCObjectStub(u"test.callback") : nullptr;

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    if (shouldRegisterFirst) {
        service.RegisterBatteryLevelCallback(callback, mechId);
    }
    service.UnRegisterBatteryLevelCallback();
}

void NotifyBatteryLevelChangeFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    int32_t batteryLevel = fdp.ConsumeIntegral<int32_t>();
    bool isCharging = fdp.ConsumeBool();

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.NotifyBatteryLevelChange(mechId, batteryLevel, isCharging);
}

void CleanMotionManagersFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    uint32_t cleanCount = fdp.ConsumeIntegralInRange<uint32_t>(MIN_QUERY_COUNT, MAX_QUERY_COUNT);

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    for (uint32_t i = 0; i < cleanCount; i++) {
        service.CleanMotionManagers();
    }
}

void GetAttachedDevicesFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    uint32_t queryCount = fdp.ConsumeIntegralInRange<uint32_t>(MIN_QUERY_COUNT, MAX_QUERY_COUNT);

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    for (uint32_t i = 0; i < queryCount; i++) {
        std::set<MechInfo> mechInfo;
        service.GetAttachedDevices(mechInfo);
    }
}

void GetTrackingEnabledFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    uint32_t queryCount = fdp.ConsumeIntegralInRange<uint32_t>(MIN_QUERY_COUNT, MAX_QUERY_COUNT);

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    for (uint32_t i = 0; i < queryCount; i++) {
        bool isEnabled = false;
        service.GetTrackingEnabled(isEnabled);
    }
}

void GetTrackingLayoutFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    uint32_t queryCount = fdp.ConsumeIntegralInRange<uint32_t>(MIN_QUERY_COUNT, MAX_QUERY_COUNT);

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    for (uint32_t i = 0; i < queryCount; i++) {
        CameraTrackingLayout layout;
        service.GetTrackingLayout(layout);
    }
}

void SearchTargetEndFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    uint32_t tokenId = fdp.ConsumeIntegral<uint32_t>();
    std::string napiCmdId = fdp.ConsumeRandomLengthString();
    int32_t targetNum = fdp.ConsumeIntegral<int32_t>();

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.SearchTargetEnd(tokenId, napiCmdId, targetNum);
}

void GetTrackingEnabledDeviceFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    uint32_t queryCount = fdp.ConsumeIntegralInRange<uint32_t>(MIN_QUERY_COUNT, MAX_QUERY_COUNT);

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    for (uint32_t i = 0; i < queryCount; i++) {
        bool isEnabled = false;
        service.GetTrackingEnabledDevice(isEnabled);
    }
}

void OnAttachStateChangeFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    AttachmentState attachmentState = static_cast<AttachmentState>(
        fdp.ConsumeIntegralInRange<int32_t>(MIN_ATTACHMENT_STATE, MAX_ATTACHMENT_STATE));
    MechInfo mechInfo;
    mechInfo.mechId = fdp.ConsumeIntegral<int32_t>();
    mechInfo.mechType = static_cast<MechType>(fdp.ConsumeIntegral<int32_t>());
    mechInfo.mechName = fdp.ConsumeRandomLengthString();
    mechInfo.mac = fdp.ConsumeRandomLengthString();
    mechInfo.state = static_cast<AttachmentState>(
        fdp.ConsumeIntegralInRange<int32_t>(MIN_ATTACHMENT_STATE, MAX_ATTACHMENT_STATE));
    mechInfo.gattCoonectState = fdp.ConsumeBool();
    mechInfo.pairState = fdp.ConsumeBool();
    mechInfo.hidState = fdp.ConsumeBool();

    MechBodyControllerService& service = MechBodyControllerService::GetInstance();
    service.OnAttachStateChange(attachmentState, mechInfo);
}


using FuzzTestFunc = void (*)(const uint8_t *, size_t);
const FuzzTestFunc FUZZ_TEST_FUNCS[] = {
    SetUserOperationFuzzTest,
    SetUserOperationNullOpFuzzTest,
    SetUserOperationJsonFuzzTest,
    OnDeviceConnectedFuzzTest,
    OnDeviceDisconnectedFuzzTest,
    SetTrackingEnabledFuzzTest,
    NotifyMechEventFuzzTest,
    RotateByDegreeFuzzTest,
    RotateByDegreeNullParamFuzzTest,
    RotateToEulerAnglesFuzzTest,
    RotateBySpeedFuzzTest,
    RotateBySpeedNullParamFuzzTest,
    StopMovingFuzzTest,
    SearchTargetFuzzTest,
    SearchTargetNullParamFuzzTest,
    SubscribeCallbackFuzzTest,
    UnSubscribeCallbackFuzzTest,
    ConnectDeviceFuzzTest,
    DisconnectDeviceFuzzTest,
    NotifyOperationResultFuzzTest,
    NotifyConnectResultFuzzTest,
    SetTrackingLayoutFuzzTest,
    GetMaxRotationTimeFuzzTest,
    GetMaxRotationSpeedFuzzTest,
    GetRotationAnglesFuzzTest,
    GetRotationDegreeLimitsFuzzTest,
    GetRotationAxesStatusFuzzTest,
    OnRotationAxesStatusChangeFuzzTest,
    RegisterAttachStateChangeCallbackFuzzTest,
    RegisterTrackingEventCallbackFuzzTest,
    UnRegisterTrackingEventCallbackFuzzTest,
    RegisterCmdChannelFuzzTest,
    RegisterRotationAxesStatusChangeCallbackFuzzTest,
    UnRegisterRotationAxesStatusChangeCallbackFuzzTest,
    GetDeviceAdsorbStateFuzzTest,
    RegisterBatteryLevelCallbackFuzzTest,
    UnRegisterBatteryLevelCallbackFuzzTest,
    NotifyBatteryLevelChangeFuzzTest,
    CleanMotionManagersFuzzTest,
    GetAttachedDevicesFuzzTest,
    GetTrackingEnabledFuzzTest,
    GetTrackingLayoutFuzzTest,
    SearchTargetEndFuzzTest,
    GetTrackingEnabledDeviceFuzzTest,
    OnAttachStateChangeFuzzTest,
};
constexpr size_t FUZZ_TEST_FUNC_COUNT = sizeof(FUZZ_TEST_FUNCS) / sizeof(FUZZ_TEST_FUNCS[0]);
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    OHOS::g_isSystemApp = fdp.ConsumeBool();

    uint8_t action = fdp.ConsumeIntegral<uint8_t>() % OHOS::FUZZ_TEST_FUNC_COUNT;
    auto remaining = fdp.ConsumeRemainingBytes<uint8_t>();
    const uint8_t *actionData = remaining.data();
    size_t actionSize = remaining.size();
    OHOS::FUZZ_TEST_FUNCS[action](actionData, actionSize);
    return 0;
}
