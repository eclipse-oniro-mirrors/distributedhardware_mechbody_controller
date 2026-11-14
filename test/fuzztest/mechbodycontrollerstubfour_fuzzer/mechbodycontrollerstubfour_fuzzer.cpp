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

#include "mechbodycontrollerstubfour_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
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
MechBodyControllerService& MechBodyControllerService::GetInstance()
{
    static auto instance = new MechBodyControllerService();
    return *instance;
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

std::string MechBodyControllerService::GetAppNameByTokenId(uint32_t tokenId)
{
    return "";
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



void StopMovingInnerFuzzTest(std::shared_ptr<MechBodyControllerStub> mechBodyControllerStubPtr,
                             FuzzedDataProvider &fdp)
{
    uint32_t code = static_cast<uint32_t>(IMechBodyControllerCode::STOP_MOVING);
    MessageParcel datas;
    datas.WriteInterfaceToken(MECH_SERVICE_IPC_TOKEN);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    datas.WriteString(cmdId);
    datas.WriteInt32(mechId);
    bool useStopCallback = fdp.ConsumeBool();
    sptr<IRemoteObject> callback = useStopCallback
        ? new IPCObjectStub(u"test.callback") : nullptr;
    datas.WriteRemoteObject(callback);
    MessageParcel reply;
    MessageOption option;

    mechBodyControllerStubPtr->OnRemoteRequest(code, datas, reply, option);
}

void GetRotationAnglesInnerFuzzTest(std::shared_ptr<MechBodyControllerStub> mechBodyControllerStubPtr,
                                    FuzzedDataProvider &fdp)
{
    uint32_t code = static_cast<uint32_t>(IMechBodyControllerCode::GET_ROTATION_ANGLES);
    MessageParcel datas;
    datas.WriteInterfaceToken(MECH_SERVICE_IPC_TOKEN);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    datas.WriteInt32(mechId);
    MessageParcel reply;
    MessageOption option;

    mechBodyControllerStubPtr->OnRemoteRequest(code, datas, reply, option);
}

void GetRotationDegreeLimitsInnerFuzzTest(std::shared_ptr<MechBodyControllerStub> mechBodyControllerStubPtr,
                                          FuzzedDataProvider &fdp)
{
    uint32_t code = static_cast<uint32_t>(IMechBodyControllerCode::GET_ROTATION_DEGREE_LIMITS);
    MessageParcel datas;
    datas.WriteInterfaceToken(MECH_SERVICE_IPC_TOKEN);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    datas.WriteInt32(mechId);
    MessageParcel reply;
    MessageOption option;

    mechBodyControllerStubPtr->OnRemoteRequest(code, datas, reply, option);
}

void GetRotationAxesStatusInnerFuzzTest(std::shared_ptr<MechBodyControllerStub> mechBodyControllerStubPtr,
                                        FuzzedDataProvider &fdp)
{
    uint32_t code = static_cast<uint32_t>(IMechBodyControllerCode::GET_ROTATION_AXES_STATUS);
    MessageParcel datas;
    datas.WriteInterfaceToken(MECH_SERVICE_IPC_TOKEN);
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    datas.WriteInt32(mechId);
    MessageParcel reply;
    MessageOption option;

    mechBodyControllerStubPtr->OnRemoteRequest(code, datas, reply, option);
}

void RotationAxesStatusChangeListenOnInnerFuzzTest(std::shared_ptr<MechBodyControllerStub> mechBodyControllerStubPtr,
                                                   FuzzedDataProvider &fdp)
{
    uint32_t code = static_cast<uint32_t>(IMechBodyControllerCode::ROTATION_AXES_STATUS_CHANGE_LISTEN_ON);
    MessageParcel datas;
    datas.WriteInterfaceToken(MECH_SERVICE_IPC_TOKEN);
    bool useAxesCallback = fdp.ConsumeBool();
    sptr<IRemoteObject> callback = useAxesCallback
        ? new IPCObjectStub(u"test.callback") : nullptr;
    datas.WriteRemoteObject(callback);
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
    uint8_t funcIndex = fdp.ConsumeIntegral<uint8_t>() % 5;
    switch (funcIndex) {
        case 0:
            OHOS::StopMovingInnerFuzzTest(mechBodyControllerStubPtr, fdp);
            break;
        case 1:
            OHOS::GetRotationAnglesInnerFuzzTest(mechBodyControllerStubPtr, fdp);
            break;
        case 2:
            OHOS::GetRotationDegreeLimitsInnerFuzzTest(mechBodyControllerStubPtr, fdp);
            break;
        case 3:
            OHOS::GetRotationAxesStatusInnerFuzzTest(mechBodyControllerStubPtr, fdp);
            break;
        case 4:
            OHOS::RotationAxesStatusChangeListenOnInnerFuzzTest(mechBodyControllerStubPtr, fdp);
            break;
        default:
            break;
    }
    return 0;
}