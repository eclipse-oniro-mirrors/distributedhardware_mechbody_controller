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

#include "mechbodycontrollerserviceone_fuzzer.h"

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

void UnRegisterAttachStateChangeCallbackFuzzTest(FuzzedDataProvider &fdp)
{
    uint32_t tokenId = fdp.ConsumeIntegral<uint32_t>();
    const sptr<OHOS::IRemoteObject> callback;

    MechBodyControllerService& mechBodyControllerService = MechBodyControllerService::GetInstance();
    mechBodyControllerService.listener_ = std::shared_ptr<IMechConnectListener>();
    mechBodyControllerService.deviceAttachCallback_[tokenId] = callback;
    mechBodyControllerService.UnRegisterAttachStateChangeCallback();
}

void OnAttachStateChangeFuzzTest(FuzzedDataProvider &fdp)
{
    std::string mechName = fdp.ConsumeRandomLengthString();
    uint32_t tokenId = fdp.ConsumeIntegral<uint32_t>();
    uint8_t enumIdx = fdp.ConsumeIntegral<uint8_t>() % 2;
    AttachmentState attachmentState = static_cast<AttachmentState>(enumIdx);
    AttachmentState state = static_cast<AttachmentState>(enumIdx);
    const sptr<OHOS::IRemoteObject> callback;
    MechInfo mechInfo;
    mechInfo.mechName = mechName;
    mechInfo.state = state;

    MechBodyControllerService& mechBodyControllerService = MechBodyControllerService::GetInstance();
    mechBodyControllerService.deviceAttachCallback_[tokenId] = callback;
    mechBodyControllerService.OnAttachStateChange(attachmentState, mechInfo);
}

void OnDeviceConnectedFuzzTest(FuzzedDataProvider &fdp)
{
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    bool isFirstConnect = fdp.ConsumeBool();
    uint32_t identifier = fdp.ConsumeIntegral<uint32_t>();

    MechBodyControllerService& mechBodyControllerService = MechBodyControllerService::GetInstance();
    mechBodyControllerService.OnDeviceConnected(mechId, isFirstConnect, identifier);
}

void GetAttachedDevicesFuzzTest(FuzzedDataProvider &fdp)
{
    std::set<MechInfo> mechInfos;
    MechInfo mechInfo;
    std::string macHash = fdp.ConsumeRandomLengthString();
    std::string mechName = fdp.ConsumeRandomLengthString();
    mechInfo.mechName = mechName;
    mechInfos.insert(mechInfo);

    MechBodyControllerService& mechBodyControllerService = MechBodyControllerService::GetInstance();
    mechBodyControllerService.GetAttachedDevices(mechInfos);
}

void SetTrackingEnabledFuzzTest(FuzzedDataProvider &fdp)
{
    bool isEnabled = fdp.ConsumeIntegral<bool>();

    MechBodyControllerService& mechBodyControllerService = MechBodyControllerService::GetInstance();
    mechBodyControllerService.SetTrackingEnabled(isEnabled);
}

void GetAppNameByTokenIdFuzzTest(FuzzedDataProvider &fdp)
{
    uint32_t tokenId = fdp.ConsumeIntegral<uint32_t>();

    MechBodyControllerService& mechBodyControllerService = MechBodyControllerService::GetInstance();
    mechBodyControllerService.GetAppNameByTokenId(tokenId);
}

void JudgeDeviceEnableSwitchAndReportFocustrackingStartEventFuzzTest(FuzzedDataProvider &fdp)
{
    uint32_t tokenId = fdp.ConsumeIntegral<uint32_t>();

    MechBodyControllerService& mechBodyControllerService = MechBodyControllerService::GetInstance();
    mechBodyControllerService.JudgeDeviceEnableSwitchAndReportFocustrackingStartEvent(tokenId);
}

void JudgeAppEnableSwitchAndReportFocustrackingStartEventFuzzTest(FuzzedDataProvider &fdp)
{
    uint32_t tokenId = fdp.ConsumeIntegral<uint32_t>();

    MechBodyControllerService& mechBodyControllerService = MechBodyControllerService::GetInstance();
    mechBodyControllerService.JudgeAppEnableSwitchAndReportFocustrackingStartEvent(tokenId);
    mechBodyControllerService.CleanMotionManagers();
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    OHOS::g_isSystemApp = fdp.ConsumeBool();
    uint8_t funcIndex = fdp.ConsumeIntegral<uint8_t>() % 8;
    switch (funcIndex) {
        case 0:
            OHOS::UnRegisterAttachStateChangeCallbackFuzzTest(fdp);
            break;
        case 1:
            OHOS::OnAttachStateChangeFuzzTest(fdp);
            break;
        case 2:
            OHOS::OnDeviceConnectedFuzzTest(fdp);
            break;
        case 3:
            OHOS::GetAttachedDevicesFuzzTest(fdp);
            break;
        case 4:
            OHOS::SetTrackingEnabledFuzzTest(fdp);
            break;
        case 5:
            OHOS::GetAppNameByTokenIdFuzzTest(fdp);
            break;
        case 6:
            OHOS::JudgeDeviceEnableSwitchAndReportFocustrackingStartEventFuzzTest(fdp);
            break;
        case 7:
            OHOS::JudgeAppEnableSwitchAndReportFocustrackingStartEventFuzzTest(fdp);
            break;
        default:
            break;
    }
    return 0;
}