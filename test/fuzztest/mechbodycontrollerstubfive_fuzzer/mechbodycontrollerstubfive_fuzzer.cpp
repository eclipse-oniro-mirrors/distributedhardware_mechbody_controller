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

#include "mechbodycontrollerstubfive_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>

#include "mechbody_controller_stub.h"
#include "mechbody_controller_service.h"
#include "mechbody_controller_ipc_interface_code.h"
#include "mechbody_controller_types.h"
#include "mechbody_controller_log.h"
#include "ipc_skeleton.h"
#include "message_option.h"
#include "message_parcel.h"
#include "securec.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "system_ability.h"

namespace OHOS {
using namespace OHOS::MechBodyController;

namespace {
enum InnerFuzzTestIndex : uint8_t {
    INNER_FUZZ_ROTATION_AXES_STATUS_CHANGE_LISTEN_OFF = 0,
    INNER_FUZZ_ROTATE_TO_EULER_ANGLES,
    INNER_FUZZ_CONNECT_DEVICE,
    INNER_FUZZ_DISCONNECT_DEVICE,
    INNER_FUZZ_TEST_COUNT
};
}  // namespace
MechBodyControllerService& MechBodyControllerService::GetInstance()
{
    static auto instance = new MechBodyControllerService();
    return *instance;
}

std::string MechBodyControllerService::GetAppNameByTokenId(uint32_t tokenId)
{
    return "";
}

MechBodyControllerService::MechBodyControllerService()
{
}

MechBodyControllerService::~MechBodyControllerService()
{
}

int32_t MechBodyControllerService::OnDeviceConnected(int32_t mechId, bool isFirstConnect,
    const uint32_t &deviceIdentifier)
{
    return 0;
}

int32_t MechBodyControllerService::RegisterAttachStateChangeCallback(const sptr<IRemoteObject> callback)
{
    return 0;
}

int32_t MechBodyControllerService::UnRegisterAttachStateChangeCallback()
{
    return 0;
}

int32_t MechBodyControllerService::OnAttachStateChange(const AttachmentState &attachmentState,
    const MechInfo &mechInfo)
{
    return 0;
}

int32_t MechBodyControllerService::GetAttachedDevices(std::set<MechInfo> &mechInfo)
{
    return 0;
}

int32_t MechBodyControllerService::SetUserOperation(const std::shared_ptr<Operation> &operation,
    const std::string &mac, const std::string &param)
{
    return 0;
}

int32_t MechBodyControllerService::SetTrackingEnabled(bool &isEnabled, bool isCapsuleSet)
{
    return 0;
}

int32_t MechBodyControllerService::GetTrackingEnabled(bool &isEnabled)
{
    return 0;
}

int32_t MechBodyControllerService::RegisterTrackingEventCallback(sptr<IRemoteObject> callback)
{
    return 0;
}

int32_t MechBodyControllerService::UnRegisterTrackingEventCallback()
{
    return 0;
}

int32_t MechBodyControllerService::SetTrackingLayout(CameraTrackingLayout &cameraTrackingLayout)
{
    return 0;
}

int32_t MechBodyControllerService::GetTrackingLayout(CameraTrackingLayout &cameraTrackingLayoutb)
{
    return 0;
}

int32_t MechBodyControllerService::RegisterCmdChannel(const sptr<IRemoteObject> callback)
{
    return 0;
}

int32_t MechBodyControllerService::RotateByDegree(const int32_t &mechId, std::string &cmdId,
    const std::shared_ptr<RotateByDegreeParam> &rotateByDegreeParam)
{
    return 0;
}
    
int32_t MechBodyControllerService::RotateToEulerAngles(const int32_t &mechId, std::string &cmdId,
    const std::shared_ptr<RotateToEulerAnglesParam> &rotateToEulerAnglesParam)
{
    return 0;
}

int32_t MechBodyControllerService::GetMaxRotationTime(const int32_t &mechId, std::shared_ptr<TimeLimit> &speedLimit)
{
    return 0;
}

int32_t MechBodyControllerService::GetMaxRotationSpeed(const int32_t &mechId, RotateSpeedLimit &speedLimit)
{
    return 0;
}

int32_t MechBodyControllerService::RotateBySpeed(const int32_t &mechId, std::string &cmdId,
    const std::shared_ptr<RotateBySpeedParam> &rotateBySpeedParam)
{
    return 0;
}

int32_t MechBodyControllerService::StopMoving(const int32_t &mechId, std::string &cmdId)
{
    return 0;
}

int32_t MechBodyControllerService::GetRotationAngles(const int32_t &mechId, std::shared_ptr<EulerAngles> &eulerAngles)
{
    return 0;
}

int32_t MechBodyControllerService::GetRotationDegreeLimits(const int32_t &mechId, RotateDegreeLimit &rotationLimit)
{
    return 0;
}

int32_t MechBodyControllerService::GetRotationAxesStatus(const int32_t &mechId, RotationAxesStatus &axesStatus)
{
    return 0;
}

int32_t MechBodyControllerService::RegisterRotationAxesStatusChangeCallback(const sptr<IRemoteObject> callback)
{
    return 0;
}

int32_t MechBodyControllerService::UnRegisterRotationAxesStatusChangeCallback()
{
    return 0;
}

int32_t MechBodyControllerService::OnDeviceDisconnected(int32_t mechId)
{
    return 0;
}

void MechBodyControllerService::OnStart(const SystemAbilityOnDemandReason &startReason) {}
void MechBodyControllerService::OnStop() {}

int32_t MechBodyControllerService::SearchTarget(std::string &napiCmdId,
    const std::shared_ptr<TargetInfo> &targetInfo, const std::shared_ptr<SearchParams> &searchParams)
{
    return 0;
}

int32_t MechBodyControllerService::Move(const int32_t &mechId, std::string &cmdId,
    const std::shared_ptr<MoveParams> &moveParams)
{
    return 0;
}

int32_t MechBodyControllerService::MoveBySpeed(const int32_t &mechId, std::string &cmdId, uint16_t duration,
    const std::shared_ptr<SpeedParams> &speedParams)
{
    return 0;
}

int32_t MechBodyControllerService::TurnBySpeed(const int32_t &mechId, std::string &cmdId,
    float angleSpeed, uint16_t duration)
{
    return 0;
}

int32_t MechBodyControllerService::IsSupportAction(const int32_t &mechId, ActionType actionType, bool &isSupport)
{
    return 0;
}

int32_t MechBodyControllerService::DoAction(const int32_t &mechId, std::string &cmdId, ActionType actionType)
{
    return 0;
}

int32_t MechBodyControllerService::SubscribeCallback(sptr<IRemoteObject> &callback, MechEventType mechEventType)
{
    return 0;
}

int32_t MechBodyControllerService::UnSubscribeCallback(MechEventType mechEventType)
{
    return 0;
}

int32_t MechBodyControllerService::ConnectDevice(std::string &cmdId,
    const std::shared_ptr<AddressInfo> &addrInfo, const std::shared_ptr<ConnectParam> &params)
{
    return 0;
}

int32_t MechBodyControllerService::DisconnectDevice(std::string &cmdId, int32_t mechId)
{
    return 0;
}

void RotationAxesStatusChangeListenOffInnerFuzzTest(std::shared_ptr<MechBodyControllerStub> mechBodyControllerStubPtr,
                                                    FuzzedDataProvider &fdp)
{
    uint32_t code = static_cast<uint32_t>(IMechBodyControllerCode::ROTATION_AXES_STATUS_CHANGE_LISTEN_OFF);
    MessageParcel datas;
    datas.WriteInterfaceToken(MECH_SERVICE_IPC_TOKEN);
    MessageParcel reply;
    MessageOption option;

    mechBodyControllerStubPtr->OnRemoteRequest(code, datas, reply, option);
}

void RotateToEulerAnglesInnerFuzzTest(std::shared_ptr<MechBodyControllerStub> mechBodyControllerStubPtr,
    FuzzedDataProvider &fdp)
{
    uint32_t code = static_cast<uint32_t>(IMechBodyControllerCode::ROTATE_TO_EULER_ANGLES);
    MessageParcel datas;
    datas.WriteInterfaceToken(MECH_SERVICE_IPC_TOKEN);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    std::string cmdId = fdp.ConsumeRandomLengthString();
    datas.WriteInt32(mechId);
    datas.WriteString(cmdId);
    RotateToEulerAnglesParam rotateParam;
    rotateParam.angles.yaw = fdp.ConsumeFloatingPoint<float>();
    rotateParam.angles.roll = fdp.ConsumeFloatingPoint<float>();
    rotateParam.angles.pitch = fdp.ConsumeFloatingPoint<float>();
    rotateParam.duration = fdp.ConsumeIntegral<int32_t>();
    datas.WriteParcelable(&rotateParam);
    bool useEulerCallback = fdp.ConsumeBool();
    sptr<IRemoteObject> callback = useEulerCallback
        ? new IPCObjectStub(u"test.callback") : nullptr;
    datas.WriteRemoteObject(callback);
    MessageParcel reply;
    MessageOption option;

    mechBodyControllerStubPtr->OnRemoteRequest(code, datas, reply, option);
}

void ConnectDeviceInnerFuzzTest(std::shared_ptr<MechBodyControllerStub> mechBodyControllerStubPtr,
                                FuzzedDataProvider &fdp)
{
    uint32_t code = static_cast<uint32_t>(IMechBodyControllerCode::CONNECT_DEVICE);
    MessageParcel datas;
    datas.WriteInterfaceToken(MECH_SERVICE_IPC_TOKEN);
    std::string cmdId = fdp.ConsumeRandomLengthString();
    datas.WriteString(cmdId);
    AddressInfo addrInfo;
    addrInfo.address = fdp.ConsumeRandomLengthString();
    addrInfo.addressType = static_cast<AddressType>(fdp.ConsumeIntegral<uint8_t>());
    datas.WriteParcelable(&addrInfo);
    ConnectParam connectParam;
    connectParam.deviceName = fdp.ConsumeRandomLengthString();
    connectParam.identifier = fdp.ConsumeIntegral<uint32_t>();
    connectParam.custdata = fdp.ConsumeRandomLengthString();
    datas.WriteParcelable(&connectParam);
    MessageParcel reply;
    MessageOption option;

    mechBodyControllerStubPtr->OnRemoteRequest(code, datas, reply, option);
}

void DisconnectDeviceInnerFuzzTest(std::shared_ptr<MechBodyControllerStub> mechBodyControllerStubPtr,
                                   FuzzedDataProvider &fdp)
{
    uint32_t code = static_cast<uint32_t>(IMechBodyControllerCode::DISCONNECT_DEVICE);
    MessageParcel datas;
    datas.WriteInterfaceToken(MECH_SERVICE_IPC_TOKEN);
    std::string cmdId = fdp.ConsumeRandomLengthString();
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    datas.WriteString(cmdId);
    datas.WriteInt32(mechId);
    MessageParcel reply;
    MessageOption option;

    mechBodyControllerStubPtr->OnRemoteRequest(code, datas, reply, option);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    auto mechBodyControllerStubPtr = std::make_shared<OHOS::MechBodyControllerService>();
    uint8_t funcIndex = fdp.ConsumeIntegral<uint8_t>() % INNER_FUZZ_TEST_COUNT;
    switch (funcIndex) {
        case INNER_FUZZ_ROTATION_AXES_STATUS_CHANGE_LISTEN_OFF:
            OHOS::RotationAxesStatusChangeListenOffInnerFuzzTest(mechBodyControllerStubPtr, fdp);
            break;
        case INNER_FUZZ_ROTATE_TO_EULER_ANGLES:
            OHOS::RotateToEulerAnglesInnerFuzzTest(mechBodyControllerStubPtr, fdp);
            break;
        case INNER_FUZZ_CONNECT_DEVICE:
            OHOS::ConnectDeviceInnerFuzzTest(mechBodyControllerStubPtr, fdp);
            break;
        case INNER_FUZZ_DISCONNECT_DEVICE:
            OHOS::DisconnectDeviceInnerFuzzTest(mechBodyControllerStubPtr, fdp);
            break;
        default:
            break;
    }
    return 0;
}