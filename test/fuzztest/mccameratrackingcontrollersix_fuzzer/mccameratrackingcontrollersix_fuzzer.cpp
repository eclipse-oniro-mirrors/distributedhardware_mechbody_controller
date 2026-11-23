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
#include "mccameratrackingcontrollersix_fuzzer.h"
#include "mc_camera_tracking_controller.h"
#include "mechbody_controller_service.h"
#include "mechbody_controller_types.h"
#include "mechbody_controller_enums.h"
#include "camera_metadata_info.h"
#include <memory>
#include <iremote_object.h>
#include "event_handler.h"

using namespace OHOS;
using namespace OHOS::MechBodyController;

namespace {
constexpr int32_t MIN_TRACKING_MODE = 0;
constexpr int32_t MAX_TRACKING_MODE = 1;
constexpr size_t MIN_ITEM_CAPACITY = 1;
constexpr size_t MAX_ITEM_CAPACITY = 100;
constexpr size_t MIN_DATA_CAPACITY = 1;
constexpr size_t MAX_DATA_CAPACITY = 1000;
constexpr size_t MAX_DETECTED_OBJECTS = 8;
constexpr int32_t MIN_OBJECT_TYPE = 0;
constexpr int32_t MAX_OBJECT_TYPE = 16;
constexpr int32_t REAR_MOUNTED_LENS = 1;
constexpr int32_t MIN_SCENE_MODE = 0;
constexpr int32_t MAX_SCENE_MODE = 24;

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
    rect.topLeftX = provider.ConsumeFloatingPointInRange<double>(0.0, 1.0);
    rect.topLeftY = provider.ConsumeFloatingPointInRange<double>(0.0, 1.0);
    rect.width = provider.ConsumeFloatingPointInRange<double>(0.0, 2.0);
    rect.height = provider.ConsumeFloatingPointInRange<double>(0.0, 2.0);
    return rect;
}

sptr<CameraStandard::MetadataObject> CreateMetadataObject(
    FuzzedDataProvider &provider, int32_t objectId)
{
    CameraStandard::Rect box = GenerateRandomRect(provider);
    int32_t objType = provider.ConsumeIntegralInRange<int32_t>(MIN_OBJECT_TYPE, MAX_OBJECT_TYPE);
    CameraStandard::MetadataObjectType type =
        static_cast<CameraStandard::MetadataObjectType>(objType);
    int32_t confidence = provider.ConsumeIntegralInRange<int32_t>(0, 100);
    bool isLockFocusTracked = provider.ConsumeBool();

    auto factory = std::make_unique<CameraStandard::MetadataObjectFactory>();
    factory->SetBox(box);
    factory->SetObjectId(objectId);
    factory->SetConfidence(confidence);
    factory->SetIsLockFocusTracked(isLockFocusTracked);
    factory->SetTimestamp(provider.ConsumeIntegral<int64_t>());

    // Set face-specific fields when type is face-related
    if (type == CameraStandard::MetadataObjectType::FACE ||
        type == CameraStandard::MetadataObjectType::BASE_FACE_DETECTION) {
        CameraStandard::Rect leftEye = GenerateRandomRect(provider);
        CameraStandard::Rect rightEye = GenerateRandomRect(provider);
        factory->SetLeftEyeBoundingBox(leftEye);
        factory->SetRightEyeBoundingBoxd(rightEye);
        factory->SetEmotion(static_cast<CameraStandard::Emotion>(provider.ConsumeIntegralInRange<int32_t>(0, 3)));
        factory->SetEmotionConfidence(provider.ConsumeIntegral<int32_t>());
        factory->SetPitchAngle(provider.ConsumeIntegral<int32_t>());
        factory->SetYawAngle(provider.ConsumeIntegral<int32_t>());
        factory->SetRollAngle(provider.ConsumeIntegral<int32_t>());
    }

    return factory->createMetadataObject(type);
}

std::vector<sptr<CameraStandard::MetadataObject>> GenerateDetectedObjects(FuzzedDataProvider &provider)
{
    std::vector<sptr<CameraStandard::MetadataObject>> objects;
    size_t count = provider.ConsumeIntegralInRange<size_t>(0, MAX_DETECTED_OBJECTS);
    for (size_t i = 0; i < count; i++) {
        objects.push_back(CreateMetadataObject(provider, static_cast<int32_t>(i)));
    }
    return objects;
}

void SetupCaptureSessionInfo(FuzzedDataProvider &provider, int32_t sessionMode)
{
    CameraStandard::CaptureSessionInfo captureSessionInfo;
    CameraStandard::OutputInfo videoOutputInfo;
    videoOutputInfo.type = CameraStandard::OutputType::VIDEO;
    videoOutputInfo.width = provider.ConsumeIntegralInRange<int32_t>(100, 4000);
    videoOutputInfo.height = provider.ConsumeIntegralInRange<int32_t>(100, 4000);
    captureSessionInfo.outputInfos.push_back(videoOutputInfo);

    CameraStandard::OutputInfo previewOutputInfo;
    previewOutputInfo.type = CameraStandard::OutputType::PREVIEW;
    previewOutputInfo.width = provider.ConsumeIntegralInRange<int32_t>(100, 4000);
    previewOutputInfo.height = provider.ConsumeIntegralInRange<int32_t>(100, 4000);
    captureSessionInfo.outputInfos.push_back(previewOutputInfo);

    captureSessionInfo.callerTokenId = provider.ConsumeIntegralInRange<int32_t>(1, 100);
    captureSessionInfo.sessionMode = sessionMode;
    captureSessionInfo.sessionId = provider.ConsumeIntegral<int32_t>();
    captureSessionInfo.position = provider.ConsumeBool() ? REAR_MOUNTED_LENS : 0;
    captureSessionInfo.zoomInfo.zoomValue = provider.ConsumeFloatingPointInRange<float>(0.5f, 10.0f);
    captureSessionInfo.zoomInfo.equivalentFocus = provider.ConsumeIntegralInRange<int32_t>(10, 200);
    captureSessionInfo.zoomInfo.videoStabilizationMode = provider.ConsumeIntegral<int32_t>();
    captureSessionInfo.zoomInfo.focusMode = provider.ConsumeIntegral<int32_t>();
    captureSessionInfo.sessionStatus = provider.ConsumeBool();

    g_cameraTrackingController->OnCaptureSessionConfiged(captureSessionInfo);
}

// Fuzz OnFocusTracking with fully populated FocusTrackingMetaInfo including detected objects
void FuzzOnFocusTrackingWithObjects(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    InitCameraTrackingController();

    // Setup camera session first to initialize currentCameraInfo_
    int32_t sessionMode = provider.ConsumeIntegralInRange<int32_t>(MIN_SCENE_MODE, MAX_SCENE_MODE);
    SetupCaptureSessionInfo(provider, sessionMode);

    CameraStandard::FocusTrackingMetaInfo info;
    info.SetTrackingObjectId(provider.ConsumeIntegral<int32_t>());

    CameraStandard::Rect trackingRegion = GenerateRandomRect(provider);
    info.SetTrackingRegion(trackingRegion);

    int32_t trackingMode = provider.ConsumeIntegralInRange<int32_t>(MIN_TRACKING_MODE, MAX_TRACKING_MODE);
    info.SetTrackingMode(static_cast<CameraStandard::FocusTrackingMode>(trackingMode));

    // Populate detected objects with various types to exercise GetTrackingTarget/ProcessTargetByType
    auto detectedObjects = GenerateDetectedObjects(provider);
    info.SetDetectedObjects(detectedObjects);

    g_cameraTrackingController->OnFocusTracking(info);
}

// Fuzz OnFocusTracking with specific object types for deeper coverage of
// GetTrackingTarget, ProcessTargetByType, SelectBestObjectByRegion,
// FindFaceForHead, FindBestFaceOrHeadForBody, FindBestMatchForBody
void FuzzOnFocusTrackingSpecificTypes(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    InitCameraTrackingController();

    // Setup camera session with CINEMATIC_VIDEO mode to hit SelectBestObjectByRegion path
    bool useCinematicMode = provider.ConsumeBool();
    int32_t sessionMode = useCinematicMode
        ? static_cast<int32_t>(CameraStandard::SceneMode::CINEMATIC_VIDEO)
        : static_cast<int32_t>(CameraStandard::SceneMode::NORMAL);
    SetupCaptureSessionInfo(provider, sessionMode);

    CameraStandard::FocusTrackingMetaInfo info;
    int32_t trackingObjectId = provider.ConsumeIntegral<int32_t>();
    info.SetTrackingObjectId(trackingObjectId);

    CameraStandard::Rect trackingRegion = GenerateRandomRect(provider);
    info.SetTrackingRegion(trackingRegion);

    int32_t trackingMode = provider.ConsumeIntegralInRange<int32_t>(MIN_TRACKING_MODE, MAX_TRACKING_MODE);
    info.SetTrackingMode(static_cast<CameraStandard::FocusTrackingMode>(trackingMode));

    // Build detected objects with overlapping bounding boxes for IOU calculation paths
    std::vector<sptr<CameraStandard::MetadataObject>> objects;

    // Create a body object
    auto bodyFactory = std::make_unique<CameraStandard::MetadataObjectFactory>();
    CameraStandard::Rect bodyRect = GenerateRandomRect(provider);
    bodyFactory->SetBox(bodyRect);
    bodyFactory->SetObjectId(0);
    bodyFactory->SetConfidence(90);
    bodyFactory->SetIsLockFocusTracked(provider.ConsumeBool());
    bodyFactory->SetTimestamp(0);
    objects.push_back(bodyFactory->createMetadataObject(CameraStandard::MetadataObjectType::HUMAN_BODY));

    // Create a face object near the body for FindBestFaceOrHeadForBody path
    auto faceFactory = std::make_unique<CameraStandard::MetadataObjectFactory>();
    CameraStandard::Rect faceRect;
    // Use similar region to body to produce non-zero IOU
    faceRect.topLeftX = provider.ConsumeBool() ? bodyRect.topLeftX : provider.ConsumeFloatingPointInRange<double>(0.0, 1.0);
    faceRect.topLeftY = provider.ConsumeBool() ? bodyRect.topLeftY : provider.ConsumeFloatingPointInRange<double>(0.0, 1.0);
    faceRect.width = provider.ConsumeBool() ? bodyRect.width : provider.ConsumeFloatingPointInRange<double>(0.0, 2.0);
    faceRect.height = provider.ConsumeBool() ? bodyRect.height : provider.ConsumeFloatingPointInRange<double>(0.0, 2.0);
    faceFactory->SetBox(faceRect);
    faceFactory->SetObjectId(1);
    faceFactory->SetConfidence(80);
    faceFactory->SetIsLockFocusTracked(false);
    faceFactory->SetTimestamp(0);
    faceFactory->SetLeftEyeBoundingBox(GenerateRandomRect(provider));
    faceFactory->SetRightEyeBoundingBoxd(GenerateRandomRect(provider));
    objects.push_back(faceFactory->createMetadataObject(CameraStandard::MetadataObjectType::FACE));

    // Create a head object near the body for FindFaceForHead path
    auto headFactory = std::make_unique<CameraStandard::MetadataObjectFactory>();
    CameraStandard::Rect headRect;
    headRect.topLeftX = provider.ConsumeBool() ? bodyRect.topLeftX : provider.ConsumeFloatingPointInRange<double>(0.0, 1.0);
    headRect.topLeftY = provider.ConsumeBool() ? bodyRect.topLeftY : provider.ConsumeFloatingPointInRange<double>(0.0, 1.0);
    headRect.width = provider.ConsumeBool() ? bodyRect.width : provider.ConsumeFloatingPointInRange<double>(0.0, 2.0);
    headRect.height = provider.ConsumeBool() ? bodyRect.height : provider.ConsumeFloatingPointInRange<double>(0.0, 2.0);
    headFactory->SetBox(headRect);
    headFactory->SetObjectId(2);
    headFactory->SetConfidence(85);
    headFactory->SetIsLockFocusTracked(false);
    headFactory->SetTimestamp(0);
    objects.push_back(headFactory->createMetadataObject(CameraStandard::MetadataObjectType::HUMAN_HEAD));

    // Optionally add a SALIENT_DETECTION object with isLockFocusTracked
    if (provider.ConsumeBool()) {
        auto salientFactory = std::make_unique<CameraStandard::MetadataObjectFactory>();
        CameraStandard::Rect salientRect = GenerateRandomRect(provider);
        salientFactory->SetBox(salientRect);
        salientFactory->SetObjectId(3);
        salientFactory->SetConfidence(70);
        salientFactory->SetIsLockFocusTracked(provider.ConsumeBool());
        salientFactory->SetTimestamp(0);
        objects.push_back(
            salientFactory->createMetadataObject(CameraStandard::MetadataObjectType::SALIENT_DETECTION));
    }

    // Optionally add a BASE_FACE_DETECTION object
    if (provider.ConsumeBool()) {
        auto baseFaceFactory = std::make_unique<CameraStandard::MetadataObjectFactory>();
        CameraStandard::Rect baseFaceRect = GenerateRandomRect(provider);
        baseFaceFactory->SetBox(baseFaceRect);
        baseFaceFactory->SetObjectId(4);
        baseFaceFactory->SetConfidence(75);
        baseFaceFactory->SetIsLockFocusTracked(false);
        baseFaceFactory->SetTimestamp(0);
        baseFaceFactory->SetLeftEyeBoundingBox(GenerateRandomRect(provider));
        baseFaceFactory->SetRightEyeBoundingBoxd(GenerateRandomRect(provider));
        objects.push_back(
            baseFaceFactory->createMetadataObject(CameraStandard::MetadataObjectType::BASE_FACE_DETECTION));
    }

    info.SetDetectedObjects(objects);

    // Call OnFocusTracking multiple times to exercise lastTrackingFrame_ and trackingRect_ paths
    int32_t iterations = provider.ConsumeIntegralInRange<int32_t>(1, 4);
    for (int32_t i = 0; i < iterations; i++) {
        g_cameraTrackingController->OnFocusTracking(info);
    }
}

// Fuzz BuildTrackingParams indirectly through OnFocusTracking with empty detected objects
// and negative trackingObjectId to exercise fallback paths
void FuzzBuildTrackingParamsFallback(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    InitCameraTrackingController();

    int32_t sessionMode = provider.ConsumeIntegralInRange<int32_t>(MIN_SCENE_MODE, MAX_SCENE_MODE);
    SetupCaptureSessionInfo(provider, sessionMode);

    CameraStandard::FocusTrackingMetaInfo info;
    // Use negative trackingObjectId to exercise fallback paths in GetTrackingTarget
    info.SetTrackingObjectId(provider.ConsumeIntegralInRange<int32_t>(-10, -1));

    CameraStandard::Rect trackingRegion = GenerateRandomRect(provider);
    info.SetTrackingRegion(trackingRegion);

    int32_t trackingMode = provider.ConsumeIntegralInRange<int32_t>(MIN_TRACKING_MODE, MAX_TRACKING_MODE);
    info.SetTrackingMode(static_cast<CameraStandard::FocusTrackingMode>(trackingMode));

    // Empty detected objects - exercise the empty path
    if (provider.ConsumeBool()) {
        std::vector<sptr<CameraStandard::MetadataObject>> emptyObjects;
        info.SetDetectedObjects(emptyObjects);
    } else {
        // Objects without matching ID - exercise GetTrackingTargetFallback
        std::vector<sptr<CameraStandard::MetadataObject>> objects;
        auto factory = std::make_unique<CameraStandard::MetadataObjectFactory>();
        CameraStandard::Rect box = GenerateRandomRect(provider);
        factory->SetBox(box);
        factory->SetObjectId(provider.ConsumeIntegralInRange<int32_t>(100, 200));
        factory->SetConfidence(provider.ConsumeIntegral<int32_t>());
        factory->SetIsLockFocusTracked(provider.ConsumeBool());
        factory->SetTimestamp(0);
        int32_t objType = provider.ConsumeIntegralInRange<int32_t>(MIN_OBJECT_TYPE, MAX_OBJECT_TYPE);
        objects.push_back(
            factory->createMetadataObject(static_cast<CameraStandard::MetadataObjectType>(objType)));
        info.SetDetectedObjects(objects);
    }

    g_cameraTrackingController->OnFocusTracking(info);
}

// Fuzz OnMetadataInfo with CameraMetadata containing FOV tag
void FuzzOnMetadataInfoWithFov(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    InitCameraTrackingController();

    // Setup camera session first
    SetupCaptureSessionInfo(provider, static_cast<int32_t>(CameraStandard::SceneMode::NORMAL));

    bool passNull = provider.ConsumeBool();
    if (passNull) {
        g_cameraTrackingController->OnMetadataInfo(nullptr);
        return;
    }

    size_t itemCapacity = provider.ConsumeIntegralInRange<size_t>(MIN_ITEM_CAPACITY, MAX_ITEM_CAPACITY);
    size_t dataCapacity = provider.ConsumeIntegralInRange<size_t>(MIN_DATA_CAPACITY, MAX_DATA_CAPACITY);
    auto metadata = std::make_shared<OHOS::Camera::CameraMetadata>(itemCapacity, dataCapacity);

    bool addFovTag = provider.ConsumeBool();
    if (addFovTag) {
        // Add FOV info tag with 2 float values to exercise the FOV extraction path
        float fovData[2] = {
            provider.ConsumeFloatingPoint<float>(),
            provider.ConsumeFloatingPoint<float>()
        };
        metadata->addEntry(OHOS_STATUS_FOV_INFOS, fovData, 2);
    }

    g_cameraTrackingController->OnMetadataInfo(metadata);
}

// Fuzz OnZoomInfoChange with valid zoom values
void FuzzOnZoomInfoChangeWithSession(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    InitCameraTrackingController();

    // Setup camera session first so currentCameraInfo_ has valid tokenId
    SetupCaptureSessionInfo(provider, static_cast<int32_t>(CameraStandard::SceneMode::VIDEO));

    int32_t sessionid = provider.ConsumeIntegral<int32_t>();
    CameraStandard::ZoomInfo zoomInfo;
    zoomInfo.zoomValue = provider.ConsumeFloatingPointInRange<float>(0.1f, 20.0f);
    zoomInfo.equivalentFocus = provider.ConsumeIntegralInRange<int32_t>(10, 200);
    zoomInfo.videoStabilizationMode = provider.ConsumeIntegralInRange<int32_t>(0, 4);
    zoomInfo.focusMode = provider.ConsumeIntegralInRange<int32_t>(-1, 10);

    g_cameraTrackingController->OnZoomInfoChange(sessionid, zoomInfo);
}

// Fuzz OnSessionStatusChange with both true and false status
void FuzzOnSessionStatusChangeWithSession(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    InitCameraTrackingController();

    // Setup camera session first
    SetupCaptureSessionInfo(provider, static_cast<int32_t>(CameraStandard::SceneMode::VIDEO));

    int32_t sessionid = provider.ConsumeIntegral<int32_t>();
    bool status = provider.ConsumeBool();
    g_cameraTrackingController->OnSessionStatusChange(sessionid, status);

    // Toggle to exercise both branches (status true then false)
    if (provider.ConsumeBool()) {
        g_cameraTrackingController->OnSessionStatusChange(sessionid, !status);
    }
}

// Fuzz UpdateCurrentCameraInfoByCaptureSessionInfo indirectly through OnCaptureSessionConfiged
// with different positions (front/back camera) and session modes
void FuzzUpdateCurrentCameraInfo(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    InitCameraTrackingController();

    CameraStandard::CaptureSessionInfo captureSessionInfo;

    // Build output infos
    CameraStandard::OutputInfo videoOutputInfo;
    videoOutputInfo.type = CameraStandard::OutputType::VIDEO;
    videoOutputInfo.width = provider.ConsumeIntegralInRange<int32_t>(100, 4000);
    videoOutputInfo.height = provider.ConsumeIntegralInRange<int32_t>(100, 4000);
    captureSessionInfo.outputInfos.push_back(videoOutputInfo);

    CameraStandard::OutputInfo previewOutputInfo;
    previewOutputInfo.type = CameraStandard::OutputType::PREVIEW;
    previewOutputInfo.width = provider.ConsumeIntegralInRange<int32_t>(100, 4000);
    previewOutputInfo.height = provider.ConsumeIntegralInRange<int32_t>(100, 4000);
    captureSessionInfo.outputInfos.push_back(previewOutputInfo);

    // Use specific scene modes for different sessionMode paths
    int32_t sceneModes[] = {
        static_cast<int32_t>(CameraStandard::SceneMode::NORMAL),
        static_cast<int32_t>(CameraStandard::SceneMode::CAPTURE),
        static_cast<int32_t>(CameraStandard::SceneMode::VIDEO),
        static_cast<int32_t>(CameraStandard::SceneMode::PORTRAIT),
        static_cast<int32_t>(CameraStandard::SceneMode::CINEMATIC_VIDEO),
    };
    int32_t modeIndex = provider.ConsumeIntegralInRange<int32_t>(0, 4);
    captureSessionInfo.sessionMode = sceneModes[modeIndex];

    captureSessionInfo.callerTokenId = provider.ConsumeIntegralInRange<int32_t>(1, 100);
    captureSessionInfo.sessionId = provider.ConsumeIntegral<int32_t>();
    captureSessionInfo.position = provider.ConsumeBool() ? REAR_MOUNTED_LENS : 0;
    captureSessionInfo.zoomInfo.zoomValue = provider.ConsumeFloatingPointInRange<float>(0.5f, 10.0f);
    captureSessionInfo.zoomInfo.equivalentFocus = provider.ConsumeIntegralInRange<int32_t>(10, 200);
    captureSessionInfo.zoomInfo.videoStabilizationMode = provider.ConsumeIntegralInRange<int32_t>(0, 4);
    captureSessionInfo.zoomInfo.focusMode = provider.ConsumeIntegral<int32_t>();
    captureSessionInfo.sessionStatus = provider.ConsumeBool();

    g_cameraTrackingController->OnCaptureSessionConfiged(captureSessionInfo);

    // Call again with different camera position to trigger front/back switch
    if (provider.ConsumeBool()) {
        captureSessionInfo.position = (captureSessionInfo.position == REAR_MOUNTED_LENS) ? 0 : REAR_MOUNTED_LENS;
        captureSessionInfo.sessionMode = sceneModes[provider.ConsumeIntegralInRange<int32_t>(0, 4)];
        g_cameraTrackingController->OnCaptureSessionConfiged(captureSessionInfo);
    }
}

// Fuzz ComputeFov indirectly by varying zoom and video stabilization modes
void FuzzComputeFovVariants(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    InitCameraTrackingController();

    // Test different video stabilization modes to exercise SensorCutForVideoMode branches
    int32_t stabModes[] = {
        static_cast<int32_t>(OHOS::MechBodyController::CameraVideoStabilizationMode::OHOS_CAMERA_VIDEO_STABILIZATION_OFF),
        static_cast<int32_t>(OHOS::MechBodyController::CameraVideoStabilizationMode::OHOS_CAMERA_VIDEO_STABILIZATION_LOW),
        static_cast<int32_t>(OHOS::MechBodyController::CameraVideoStabilizationMode::OHOS_CAMERA_VIDEO_STABILIZATION_MIDDLE),
        static_cast<int32_t>(OHOS::MechBodyController::CameraVideoStabilizationMode::OHOS_CAMERA_VIDEO_STABILIZATION_HIGH),
        static_cast<int32_t>(OHOS::MechBodyController::CameraVideoStabilizationMode::OHOS_CAMERA_VIDEO_STABILIZATION_AUTO),
    };

    CameraStandard::CaptureSessionInfo captureSessionInfo;
    CameraStandard::OutputInfo videoOutputInfo;
    videoOutputInfo.type = CameraStandard::OutputType::VIDEO;
    videoOutputInfo.width = provider.ConsumeIntegralInRange<int32_t>(100, 4000);
    videoOutputInfo.height = provider.ConsumeIntegralInRange<int32_t>(100, 4000);
    captureSessionInfo.outputInfos.push_back(videoOutputInfo);

    captureSessionInfo.callerTokenId = provider.ConsumeIntegralInRange<int32_t>(1, 100);
    captureSessionInfo.sessionId = provider.ConsumeIntegral<int32_t>();
    captureSessionInfo.position = provider.ConsumeBool() ? REAR_MOUNTED_LENS : 0;

    int32_t modeIndex = provider.ConsumeIntegralInRange<int32_t>(0, 4);
    captureSessionInfo.sessionMode = (modeIndex <= 1)
        ? static_cast<int32_t>(CameraStandard::SceneMode::VIDEO)
        : static_cast<int32_t>(CameraStandard::SceneMode::CINEMATIC_VIDEO);

    int32_t stabIndex = provider.ConsumeIntegralInRange<int32_t>(0, 4);
    captureSessionInfo.zoomInfo.zoomValue = provider.ConsumeFloatingPointInRange<float>(0.5f, 10.0f);
    captureSessionInfo.zoomInfo.equivalentFocus = provider.ConsumeIntegralInRange<int32_t>(10, 200);
    captureSessionInfo.zoomInfo.videoStabilizationMode = stabModes[stabIndex];
    captureSessionInfo.zoomInfo.focusMode = 1;
    captureSessionInfo.sessionStatus = true;

    g_cameraTrackingController->OnCaptureSessionConfiged(captureSessionInfo);
}

// Fuzz CalculateIOU indirectly through OnFocusTracking with overlapping rects
void FuzzCalculateIOUViaTracking(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    InitCameraTrackingController();

    int32_t sessionMode = provider.ConsumeIntegralInRange<int32_t>(MIN_SCENE_MODE, MAX_SCENE_MODE);
    SetupCaptureSessionInfo(provider, sessionMode);

    // Create two FocusTrackingMetaInfo calls with overlapping rects to exercise
    // IOU calculation in IsAllowedConversion and CalculateIOU
    for (int32_t iter = 0; iter < 2; iter++) {
        CameraStandard::FocusTrackingMetaInfo info;
        info.SetTrackingObjectId(provider.ConsumeIntegralInRange<int32_t>(0, 5));

        CameraStandard::Rect trackingRegion = GenerateRandomRect(provider);
        info.SetTrackingRegion(trackingRegion);

        int32_t trackingMode = provider.ConsumeIntegralInRange<int32_t>(MIN_TRACKING_MODE, MAX_TRACKING_MODE);
        info.SetTrackingMode(static_cast<CameraStandard::FocusTrackingMode>(trackingMode));

        // Create overlapping objects to exercise CalculateIOU paths
        std::vector<sptr<CameraStandard::MetadataObject>> objects;
        CameraStandard::Rect baseRect = GenerateRandomRect(provider);

        // Create a face object with the base rect
        auto faceFactory = std::make_unique<CameraStandard::MetadataObjectFactory>();
        faceFactory->SetBox(baseRect);
        faceFactory->SetObjectId(0);
        faceFactory->SetConfidence(90);
        faceFactory->SetIsLockFocusTracked(false);
        faceFactory->SetTimestamp(0);
        objects.push_back(faceFactory->createMetadataObject(CameraStandard::MetadataObjectType::FACE));

        // Create another face with overlapping rect for IOU > threshold
        if (provider.ConsumeBool()) {
            auto faceFactory2 = std::make_unique<CameraStandard::MetadataObjectFactory>();
            CameraStandard::Rect overlapRect;
            // Make overlapping rect by using similar coordinates
            overlapRect.topLeftX = baseRect.topLeftX + provider.ConsumeFloatingPointInRange<double>(-0.1, 0.1);
            overlapRect.topLeftY = baseRect.topLeftY + provider.ConsumeFloatingPointInRange<double>(-0.1, 0.1);
            overlapRect.width = baseRect.width + provider.ConsumeFloatingPointInRange<double>(-0.1, 0.1);
            overlapRect.height = baseRect.height + provider.ConsumeFloatingPointInRange<double>(-0.1, 0.1);
            faceFactory2->SetBox(overlapRect);
            faceFactory2->SetObjectId(1);
            faceFactory2->SetConfidence(80);
            faceFactory2->SetIsLockFocusTracked(false);
            faceFactory2->SetTimestamp(0);
            objects.push_back(faceFactory2->createMetadataObject(CameraStandard::MetadataObjectType::FACE));
        }

        info.SetDetectedObjects(objects);
        g_cameraTrackingController->OnFocusTracking(info);
    }
}

// Fuzz CinematicVideoModeTrackingTargetFilter by calling OnFocusTracking
// in CINEMATIC_VIDEO mode with isSalientDetectionLocked scenarios
void FuzzCinematicVideoFilter(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    InitCameraTrackingController();

    // Must use CINEMATIC_VIDEO mode
    SetupCaptureSessionInfo(provider, static_cast<int32_t>(CameraStandard::SceneMode::CINEMATIC_VIDEO));

    // First call with SALIENT_DETECTION + isLockFocusTracked=true to set isSalientDetectionLocked_
    CameraStandard::FocusTrackingMetaInfo info1;
    info1.SetTrackingObjectId(provider.ConsumeIntegralInRange<int32_t>(0, 5));
    CameraStandard::Rect region1 = GenerateRandomRect(provider);
    info1.SetTrackingRegion(region1);
    info1.SetTrackingMode(CameraStandard::FocusTrackingMode::FOCUS_TRACKING_MODE_AUTO);

    std::vector<sptr<CameraStandard::MetadataObject>> objects1;
    auto salientFactory = std::make_unique<CameraStandard::MetadataObjectFactory>();
    salientFactory->SetBox(GenerateRandomRect(provider));
    salientFactory->SetObjectId(0);
    salientFactory->SetConfidence(80);
    salientFactory->SetIsLockFocusTracked(true); // Set lock focus tracked
    salientFactory->SetTimestamp(0);
    objects1.push_back(
        salientFactory->createMetadataObject(CameraStandard::MetadataObjectType::SALIENT_DETECTION));
    info1.SetDetectedObjects(objects1);

    g_cameraTrackingController->OnFocusTracking(info1);

    // Second call with different target to exercise CinematicVideoModeTrackingTargetFilter
    CameraStandard::FocusTrackingMetaInfo info2;
    info2.SetTrackingObjectId(provider.ConsumeIntegralInRange<int32_t>(0, 5));
    CameraStandard::Rect region2 = GenerateRandomRect(provider);
    info2.SetTrackingRegion(region2);
    info2.SetTrackingMode(static_cast<CameraStandard::FocusTrackingMode>(
        provider.ConsumeIntegralInRange<int32_t>(MIN_TRACKING_MODE, MAX_TRACKING_MODE)));

    std::vector<sptr<CameraStandard::MetadataObject>> objects2;
    // Create a body object
    auto bodyFactory = std::make_unique<CameraStandard::MetadataObjectFactory>();
    bodyFactory->SetBox(GenerateRandomRect(provider));
    bodyFactory->SetObjectId(1);
    bodyFactory->SetConfidence(85);
    bodyFactory->SetIsLockFocusTracked(false);
    bodyFactory->SetTimestamp(0);
    objects2.push_back(bodyFactory->createMetadataObject(CameraStandard::MetadataObjectType::HUMAN_BODY));

    // Create a face object near the body
    auto faceFactory2 = std::make_unique<CameraStandard::MetadataObjectFactory>();
    CameraStandard::Rect faceRect2 = GenerateRandomRect(provider);
    faceFactory2->SetBox(faceRect2);
    faceFactory2->SetObjectId(2);
    faceFactory2->SetConfidence(80);
    faceFactory2->SetIsLockFocusTracked(false);
    faceFactory2->SetTimestamp(0);
    faceFactory2->SetLeftEyeBoundingBox(GenerateRandomRect(provider));
    faceFactory2->SetRightEyeBoundingBoxd(GenerateRandomRect(provider));
    objects2.push_back(faceFactory2->createMetadataObject(CameraStandard::MetadataObjectType::FACE));

    // Create a head object
    auto headFactory2 = std::make_unique<CameraStandard::MetadataObjectFactory>();
    headFactory2->SetBox(GenerateRandomRect(provider));
    headFactory2->SetObjectId(3);
    headFactory2->SetConfidence(75);
    headFactory2->SetIsLockFocusTracked(false);
    headFactory2->SetTimestamp(0);
    objects2.push_back(headFactory2->createMetadataObject(CameraStandard::MetadataObjectType::HUMAN_HEAD));

    info2.SetDetectedObjects(objects2);
    g_cameraTrackingController->OnFocusTracking(info2);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzOnFocusTrackingWithObjects(data, size);
    FuzzOnFocusTrackingSpecificTypes(data, size);
    FuzzBuildTrackingParamsFallback(data, size);
    FuzzOnMetadataInfoWithFov(data, size);
    FuzzOnZoomInfoChangeWithSession(data, size);
    FuzzOnSessionStatusChangeWithSession(data, size);
    FuzzUpdateCurrentCameraInfo(data, size);
    FuzzComputeFovVariants(data, size);
    FuzzCalculateIOUViaTracking(data, size);
    FuzzCinematicVideoFilter(data, size);
    return 0;
}
