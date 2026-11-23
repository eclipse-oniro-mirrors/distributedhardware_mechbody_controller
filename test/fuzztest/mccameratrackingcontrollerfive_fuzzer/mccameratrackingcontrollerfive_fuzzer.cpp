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
#include "mccameratrackingcontrollerfive_fuzzer.h"
#include "mc_camera_tracking_controller.h"
#include "mechbody_controller_service.h"
#include "mechbody_controller_types.h"
#include "mechbody_controller_enums.h"
#include <memory>
#include <iremote_object.h>
#include "event_handler.h"
#include "common_event.h"

using namespace OHOS;
using namespace OHOS::MechBodyController;
using namespace EventFwk;

namespace {
constexpr int32_t MIN_TRACKING_MODE = 0;
constexpr int32_t MAX_TRACKING_MODE = 2;
constexpr size_t MIN_ITEM_CAPACITY = 1;
constexpr size_t MAX_ITEM_CAPACITY = 100;
constexpr size_t MIN_DATA_CAPACITY = 1;
constexpr size_t MAX_DATA_CAPACITY = 1000;
constexpr size_t MAX_ACTION_STRING_LENGTH = 64;

McCameraTrackingController* g_cameraTrackingController = nullptr;

void InitCameraTrackingController()
{
    if (g_cameraTrackingController == nullptr) {
        g_cameraTrackingController = &McCameraTrackingController::GetInstance();
    }
}

CameraStandard::Rect GenerateRandomRect(FuzzedDataProvider &provider)
{
    CameraStandard::Rect rect;
    rect.topLeftX = provider.ConsumeFloatingPointInRange<float>(0.0f, 1.0f);
    rect.topLeftY = provider.ConsumeFloatingPointInRange<float>(0.0f, 1.0f);
    rect.width = provider.ConsumeFloatingPointInRange<float>(0.0f, 1.0f);
    rect.height = provider.ConsumeFloatingPointInRange<float>(0.0f, 1.0f);
    return rect;
}

void FuzzOnFocusTrackingInfo(FuzzedDataProvider &fdp)
{
    InitCameraTrackingController();
    CameraStandard::FocusTrackingMetaInfo info;
    info.SetTrackingObjectId(fdp.ConsumeIntegral<int32_t>());

    CameraStandard::Rect trackingRegion = GenerateRandomRect(fdp);
    info.SetTrackingRegion(trackingRegion);

    int32_t trackingMode = fdp.ConsumeIntegralInRange<int32_t>(MIN_TRACKING_MODE, MAX_TRACKING_MODE);
    info.SetTrackingMode(static_cast<CameraStandard::FocusTrackingMode>(trackingMode));
    g_cameraTrackingController->OnFocusTracking(info);
}

void FuzzOnCaptureSessionConfiged(FuzzedDataProvider &fdp)
{
    InitCameraTrackingController();
    CameraStandard::CaptureSessionInfo captureSessionInfo;

    CameraStandard::OutputInfo videoOutputInfo;
    videoOutputInfo.type = CameraStandard::OutputType::VIDEO;
    videoOutputInfo.width = fdp.ConsumeIntegral<int32_t>();
    videoOutputInfo.height = fdp.ConsumeIntegral<int32_t>();
    captureSessionInfo.outputInfos.push_back(videoOutputInfo);

    CameraStandard::OutputInfo previewOutputInfo;
    previewOutputInfo.type = CameraStandard::OutputType::PREVIEW;
    previewOutputInfo.width = fdp.ConsumeIntegral<int32_t>();
    previewOutputInfo.height = fdp.ConsumeIntegral<int32_t>();
    captureSessionInfo.outputInfos.push_back(previewOutputInfo);

    int32_t dataRangeMin = 1;
    int32_t dataRangeMax = 6;
    captureSessionInfo.callerTokenId = fdp.ConsumeIntegralInRange<int32_t>(dataRangeMin, dataRangeMax);
    captureSessionInfo.sessionMode = CameraStandard::SceneMode::CINEMATIC_VIDEO;
    captureSessionInfo.sessionId = fdp.ConsumeIntegral<int32_t>();
    g_cameraTrackingController->OnCaptureSessionConfiged(captureSessionInfo);
}

void FuzzOnZoomInfoChange(FuzzedDataProvider &fdp)
{
    InitCameraTrackingController();
    int32_t sessionid = fdp.ConsumeIntegral<int32_t>();
    CameraStandard::ZoomInfo zoomInfo;
    zoomInfo.zoomValue = fdp.ConsumeFloatingPoint<float>();
    zoomInfo.equivalentFocus = fdp.ConsumeIntegral<int32_t>();
    zoomInfo.videoStabilizationMode = fdp.ConsumeIntegral<int32_t>();
    zoomInfo.focusMode = fdp.ConsumeIntegral<int32_t>();
    g_cameraTrackingController->OnZoomInfoChange(sessionid, zoomInfo);
}

void FuzzOnSessionStatusChange(FuzzedDataProvider &fdp)
{
    InitCameraTrackingController();
    int32_t sessionid = fdp.ConsumeIntegral<int32_t>();
    bool status = fdp.ConsumeBool();
    g_cameraTrackingController->OnSessionStatusChange(sessionid, status);
}

void FuzzOnMetadataInfo(FuzzedDataProvider &fdp)
{
    InitCameraTrackingController();
    bool passNull = fdp.ConsumeBool();
    if (passNull) {
        g_cameraTrackingController->OnMetadataInfo(nullptr);
    } else {
        size_t itemCapacity = fdp.ConsumeIntegralInRange<size_t>(MIN_ITEM_CAPACITY, MAX_ITEM_CAPACITY);
        size_t dataCapacity = fdp.ConsumeIntegralInRange<size_t>(MIN_DATA_CAPACITY, MAX_DATA_CAPACITY);
        auto metadata = std::make_shared<OHOS::Camera::CameraMetadata>(itemCapacity, dataCapacity);
        g_cameraTrackingController->OnMetadataInfo(metadata);
    }
}

void FuzzOnReceiveEvent(FuzzedDataProvider &fdp)
{
    InitCameraTrackingController();
    std::string action = fdp.ConsumeRandomLengthString(MAX_ACTION_STRING_LENGTH);
    CommonEventData eventData;
    eventData.SetCode(fdp.ConsumeIntegral<int32_t>());
    MechBodyEventBaseService::GetInstance().OnReceiveEvent(action, eventData);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    uint8_t funcIndex = fdp.ConsumeIntegral<uint8_t>() % 6;
    switch (funcIndex) {
        case 0:
            FuzzOnFocusTrackingInfo(fdp);
            break;
        case 1:
            FuzzOnCaptureSessionConfiged(fdp);
            break;
        case 2:
            FuzzOnZoomInfoChange(fdp);
            break;
        case 3:
            FuzzOnSessionStatusChange(fdp);
            break;
        case 4:
            FuzzOnMetadataInfo(fdp);
            break;
        case 5:
            FuzzOnReceiveEvent(fdp);
            break;
        default:
            break;
    }
    return 0;
}