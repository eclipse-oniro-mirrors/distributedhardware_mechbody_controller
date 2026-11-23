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
#include <cstdlib>
#include <memory>
#include <iremote_object.h>
#include "refbase.h"
#include "event_handler.h"

using namespace OHOS;
using namespace OHOS::MechBodyController;

namespace {
using StabMode = OHOS::MechBodyController::CameraVideoStabilizationMode;
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
constexpr int32_t MIN_RECT_COORD = 0;
constexpr int32_t MAX_RECT_COORD = 1;
constexpr double MIN_RECT_SIZE = 0.0;
constexpr double MAX_RECT_SIZE = 2.0;
constexpr double OVERLAP_RECT_DELTA = 0.1;
constexpr int32_t MIN_STREAM_RESOLUTION = 100;
constexpr int32_t MAX_STREAM_RESOLUTION = 4000;
constexpr int32_t MIN_EQUIVALENT_FOCUS = 10;
constexpr int32_t MAX_EQUIVALENT_FOCUS = 200;
constexpr int32_t MIN_MODE_INDEX = 0;
constexpr int32_t MAX_MODE_INDEX = 4;
constexpr int32_t MIN_FOCUS_MODE = -1;
constexpr int32_t MAX_FOCUS_MODE = 10;
constexpr int32_t MIN_METADATA_OBJECT_ID = 100;
constexpr int32_t MAX_METADATA_OBJECT_ID = 200;
constexpr int32_t HEAD_OBJECT_ID = 2;
constexpr int32_t SALIENT_OBJECT_ID = 3;
constexpr int32_t BASE_FACE_OBJECT_ID = 4;
constexpr int32_t CONFIDENCE_LOW = 70;
constexpr int32_t MIN_CONFIDENCE_VALUE = 0;
constexpr int32_t MAX_CONFIDENCE_VALUE = 100;
constexpr int32_t MIN_ON_FOCUS_ITERATIONS = 1;
constexpr int32_t MAX_ON_FOCUS_ITERATIONS = 4;
constexpr int32_t MIN_INVALID_OBJECT_ID = -10;
constexpr int32_t MAX_INVALID_OBJECT_ID = -1;
constexpr int32_t CONFIDENCE_FAIR = 75;
constexpr int32_t CONFIDENCE_MEDIUM = 80;
constexpr int32_t CONFIDENCE_HIGH = 85;
constexpr int32_t CONFIDENCE_VERY_HIGH = 90;
constexpr int32_t MIN_EMOTION_TYPE = 0;
constexpr int32_t MAX_EMOTION_TYPE = 3;
constexpr int32_t MIN_TRACKING_OBJECT_ID = 0;
constexpr int32_t MAX_TRACKING_OBJECT_ID = 5;
constexpr int32_t OBJECT_PAIR_COUNT = 2;
constexpr size_t FOV_VALUE_COUNT = 2;

McCameraTrackingController* g_cameraTrackingController = nullptr;

void CleanupCameraTrackingController()
{
    // Ensure all pending tasks posted to eventHandler_ (e.g. SEARCH_TARGET_TASK_NAME,
    // PREDICTION_TASK_NAME) are removed before the singleton is destructed.
    // Without this, the background EventRunner may execute lambdas capturing `this`
    // after currentCameraInfo_/lastTrackingFrame_ have been freed, causing heap-use-after-free.
    if (g_cameraTrackingController != nullptr) {
        g_cameraTrackingController->UnInit();
        g_cameraTrackingController = nullptr;
    }
}

void InitCameraTrackingController()
{
    if (g_cameraTrackingController == nullptr) {
        g_cameraTrackingController = &McCameraTrackingController::GetInstance();
    }
}

bool IsControllerValid()
{
    return g_cameraTrackingController != nullptr;
}

CameraStandard::Rect GenerateRandomRect(FuzzedDataProvider &fdp)
{
    CameraStandard::Rect rect;
    rect.topLeftX = fdp.ConsumeFloatingPointInRange<double>(MIN_RECT_COORD, MAX_RECT_COORD);
    rect.topLeftY = fdp.ConsumeFloatingPointInRange<double>(MIN_RECT_COORD, MAX_RECT_COORD);
    rect.width = fdp.ConsumeFloatingPointInRange<double>(MIN_RECT_SIZE, MAX_RECT_SIZE);
    rect.height = fdp.ConsumeFloatingPointInRange<double>(MIN_RECT_SIZE, MAX_RECT_SIZE);
    return rect;
}

sptr<CameraStandard::MetadataObject> CreateMetadataObject(
    FuzzedDataProvider &fdp, int32_t objectId)
{
    CameraStandard::Rect box = GenerateRandomRect(fdp);
    int32_t objType = fdp.ConsumeIntegralInRange<int32_t>(MIN_OBJECT_TYPE, MAX_OBJECT_TYPE);
    CameraStandard::MetadataObjectType type =
        static_cast<CameraStandard::MetadataObjectType>(objType);
    int32_t confidence = fdp.ConsumeIntegralInRange<int32_t>(MIN_CONFIDENCE_VALUE, MAX_CONFIDENCE_VALUE);
    bool isLockFocusTracked = fdp.ConsumeBool();

    auto factory = OHOS::sptr<CameraStandard::MetadataObjectFactory>(new CameraStandard::MetadataObjectFactory());
    factory->SetBox(box);
    factory->SetObjectId(objectId);
    factory->SetConfidence(confidence);
    factory->SetIsLockFocusTracked(isLockFocusTracked);
    factory->SetTimestamp(fdp.ConsumeIntegral<int64_t>());

    // Set face-specific fields when type is face-related
    if (type == CameraStandard::MetadataObjectType::FACE ||
        type == CameraStandard::MetadataObjectType::BASE_FACE_DETECTION) {
        CameraStandard::Rect leftEye = GenerateRandomRect(fdp);
        CameraStandard::Rect rightEye = GenerateRandomRect(fdp);
        factory->SetLeftEyeBoundingBox(leftEye);
        factory->SetRightEyeBoundingBoxd(rightEye);
        int32_t emotionType = fdp.ConsumeIntegralInRange<int32_t>(MIN_EMOTION_TYPE, MAX_EMOTION_TYPE);
        factory->SetEmotion(static_cast<CameraStandard::Emotion>(emotionType));
        factory->SetEmotionConfidence(fdp.ConsumeIntegral<int32_t>());
        factory->SetPitchAngle(fdp.ConsumeIntegral<int32_t>());
        factory->SetYawAngle(fdp.ConsumeIntegral<int32_t>());
        factory->SetRollAngle(fdp.ConsumeIntegral<int32_t>());
    }

    return factory->createMetadataObject(type);
}

std::vector<sptr<CameraStandard::MetadataObject>> GenerateDetectedObjects(FuzzedDataProvider &fdp)
{
    std::vector<sptr<CameraStandard::MetadataObject>> objects;
    size_t count = fdp.ConsumeIntegralInRange<size_t>(0, MAX_DETECTED_OBJECTS);
    for (size_t i = 0; i < count; i++) {
        objects.push_back(CreateMetadataObject(fdp, static_cast<int32_t>(i)));
    }
    return objects;
}

void SetupCaptureSessionInfo(FuzzedDataProvider &fdp, int32_t sessionMode)
{
    CameraStandard::CaptureSessionInfo captureSessionInfo;
    CameraStandard::OutputInfo videoOutputInfo;
    videoOutputInfo.type = CameraStandard::OutputType::VIDEO;
    videoOutputInfo.width = fdp.ConsumeIntegralInRange<int32_t>(MIN_STREAM_RESOLUTION, MAX_STREAM_RESOLUTION);
    videoOutputInfo.height = fdp.ConsumeIntegralInRange<int32_t>(MIN_STREAM_RESOLUTION, MAX_STREAM_RESOLUTION);
    captureSessionInfo.outputInfos.push_back(videoOutputInfo);

    CameraStandard::OutputInfo previewOutputInfo;
    previewOutputInfo.type = CameraStandard::OutputType::PREVIEW;
    previewOutputInfo.width = fdp.ConsumeIntegralInRange<int32_t>(MIN_STREAM_RESOLUTION, MAX_STREAM_RESOLUTION);
    previewOutputInfo.height = fdp.ConsumeIntegralInRange<int32_t>(MIN_STREAM_RESOLUTION, MAX_STREAM_RESOLUTION);
    captureSessionInfo.outputInfos.push_back(previewOutputInfo);

    captureSessionInfo.callerTokenId = 0;
    captureSessionInfo.sessionMode = sessionMode;
    captureSessionInfo.sessionId = fdp.ConsumeIntegral<int32_t>();
    captureSessionInfo.position = fdp.ConsumeBool() ? REAR_MOUNTED_LENS : 0;
    captureSessionInfo.zoomInfo.zoomValue = fdp.ConsumeFloatingPointInRange<float>(0.5f, 10.0f);
    captureSessionInfo.zoomInfo.equivalentFocus =
        fdp.ConsumeIntegralInRange<int32_t>(MIN_EQUIVALENT_FOCUS, MAX_EQUIVALENT_FOCUS);
    captureSessionInfo.zoomInfo.videoStabilizationMode = fdp.ConsumeIntegral<int32_t>();
    captureSessionInfo.zoomInfo.focusMode = fdp.ConsumeIntegral<int32_t>();
    captureSessionInfo.sessionStatus = fdp.ConsumeBool();

    if (!IsControllerValid()) {
        return;
    }
    g_cameraTrackingController->OnCaptureSessionConfiged(captureSessionInfo);
}

// Fuzz OnFocusTracking with fully populated FocusTrackingMetaInfo including detected objects
void FuzzOnFocusTrackingWithObjects(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    InitCameraTrackingController();
    if (!IsControllerValid()) {
        return;
    }

    // Setup camera session first to initialize currentCameraInfo_
    int32_t sessionMode = fdp.ConsumeIntegralInRange<int32_t>(MIN_SCENE_MODE, MAX_SCENE_MODE);
    SetupCaptureSessionInfo(fdp, sessionMode);

    CameraStandard::FocusTrackingMetaInfo info;
    info.SetTrackingObjectId(fdp.ConsumeIntegral<int32_t>());

    CameraStandard::Rect trackingRegion = GenerateRandomRect(fdp);
    info.SetTrackingRegion(trackingRegion);

    int32_t trackingMode = fdp.ConsumeIntegralInRange<int32_t>(MIN_TRACKING_MODE, MAX_TRACKING_MODE);
    info.SetTrackingMode(static_cast<CameraStandard::FocusTrackingMode>(trackingMode));

    // Populate detected objects with various types to exercise GetTrackingTarget/ProcessTargetByType
    auto detectedObjects = GenerateDetectedObjects(fdp);
    info.SetDetectedObjects(detectedObjects);

    g_cameraTrackingController->OnFocusTracking(info);
}

// Fuzz OnFocusTracking with specific object types for deeper coverage of
// GetTrackingTarget, ProcessTargetByType, SelectBestObjectByRegion,
// FindFaceForHead, FindBestFaceOrHeadForBody, FindBestMatchForBody

CameraStandard::Rect CreateSimilarRect(FuzzedDataProvider &fdp, const CameraStandard::Rect &baseRect)
{
    CameraStandard::Rect rect;
    rect.topLeftX = fdp.ConsumeBool()
        ? baseRect.topLeftX
        : fdp.ConsumeFloatingPointInRange<double>(MIN_RECT_COORD, MAX_RECT_COORD);
    rect.topLeftY = fdp.ConsumeBool()
        ? baseRect.topLeftY
        : fdp.ConsumeFloatingPointInRange<double>(MIN_RECT_COORD, MAX_RECT_COORD);
    rect.width = fdp.ConsumeBool()
        ? baseRect.width
        : fdp.ConsumeFloatingPointInRange<double>(MIN_RECT_SIZE, MAX_RECT_SIZE);
    rect.height = fdp.ConsumeBool()
        ? baseRect.height
        : fdp.ConsumeFloatingPointInRange<double>(MIN_RECT_SIZE, MAX_RECT_SIZE);
    return rect;
}

sptr<CameraStandard::MetadataObject> CreateObject(FuzzedDataProvider &fdp,
    CameraStandard::MetadataObjectType type, int32_t objectId, int32_t confidence, bool lockFocusTracked)
{
    auto factory =
        OHOS::sptr<CameraStandard::MetadataObjectFactory>(new CameraStandard::MetadataObjectFactory());
    factory->SetBox(GenerateRandomRect(fdp));
    factory->SetObjectId(objectId);
    factory->SetConfidence(confidence);
    factory->SetIsLockFocusTracked(lockFocusTracked);
    factory->SetTimestamp(0);
    return factory->createMetadataObject(type);
}

sptr<CameraStandard::MetadataObject> CreateFaceObject(FuzzedDataProvider &fdp,
    const CameraStandard::Rect &faceRect, int32_t objectId, int32_t confidence)
{
    auto factory =
        OHOS::sptr<CameraStandard::MetadataObjectFactory>(new CameraStandard::MetadataObjectFactory());
    factory->SetBox(faceRect);
    factory->SetObjectId(objectId);
    factory->SetConfidence(confidence);
    factory->SetIsLockFocusTracked(false);
    factory->SetTimestamp(0);
    factory->SetLeftEyeBoundingBox(GenerateRandomRect(fdp));
    factory->SetRightEyeBoundingBoxd(GenerateRandomRect(fdp));
    return factory->createMetadataObject(CameraStandard::MetadataObjectType::FACE);
}

void FuzzOnFocusTrackingSpecificTypes(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    InitCameraTrackingController();
    if (!IsControllerValid()) {
        return;
    }

    // Setup camera session with CINEMATIC_VIDEO mode to hit SelectBestObjectByRegion path
    bool useCinematicMode = fdp.ConsumeBool();
    int32_t sessionMode = useCinematicMode
        ? static_cast<int32_t>(CameraStandard::SceneMode::CINEMATIC_VIDEO)
        : static_cast<int32_t>(CameraStandard::SceneMode::NORMAL);
    SetupCaptureSessionInfo(fdp, sessionMode);

    CameraStandard::FocusTrackingMetaInfo info;
    info.SetTrackingObjectId(fdp.ConsumeIntegral<int32_t>());
    info.SetTrackingRegion(GenerateRandomRect(fdp));
    info.SetTrackingMode(static_cast<CameraStandard::FocusTrackingMode>(
        fdp.ConsumeIntegralInRange<int32_t>(MIN_TRACKING_MODE, MAX_TRACKING_MODE)));

    // Build detected objects with overlapping bounding boxes for IOU calculation paths
    std::vector<sptr<CameraStandard::MetadataObject>> objects;
    CameraStandard::Rect bodyRect = GenerateRandomRect(fdp);
    objects.push_back(CreateObject(fdp, CameraStandard::MetadataObjectType::HUMAN_BODY, 0,
        CONFIDENCE_VERY_HIGH, fdp.ConsumeBool()));
    objects.push_back(CreateFaceObject(fdp, CreateSimilarRect(fdp, bodyRect), 1, CONFIDENCE_MEDIUM));
    objects.push_back(CreateObject(fdp, CameraStandard::MetadataObjectType::HUMAN_HEAD, HEAD_OBJECT_ID,
        CONFIDENCE_HIGH, false));

    // Optionally add a SALIENT_DETECTION object with isLockFocusTracked
    if (fdp.ConsumeBool()) {
        objects.push_back(CreateObject(fdp, CameraStandard::MetadataObjectType::SALIENT_DETECTION,
            SALIENT_OBJECT_ID, CONFIDENCE_LOW, fdp.ConsumeBool()));
    }

    // Optionally add a BASE_FACE_DETECTION object
    if (fdp.ConsumeBool()) {
        objects.push_back(CreateFaceObject(fdp, GenerateRandomRect(fdp), BASE_FACE_OBJECT_ID,
            CONFIDENCE_FAIR));
    }

    info.SetDetectedObjects(objects);

    // Call OnFocusTracking multiple times to exercise lastTrackingFrame_ and trackingRect_ paths
    int32_t iterations = fdp.ConsumeIntegralInRange<int32_t>(MIN_ON_FOCUS_ITERATIONS, MAX_ON_FOCUS_ITERATIONS);
    for (int32_t i = 0; i < iterations; i++) {
        g_cameraTrackingController->OnFocusTracking(info);
    }
}

// Fuzz BuildTrackingParams indirectly through OnFocusTracking with empty detected objects
// and negative trackingObjectId to exercise fallback paths
void FuzzBuildTrackingParamsFallback(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    InitCameraTrackingController();
    if (!IsControllerValid()) {
        return;
    }

    int32_t sessionMode = fdp.ConsumeIntegralInRange<int32_t>(MIN_SCENE_MODE, MAX_SCENE_MODE);
    SetupCaptureSessionInfo(fdp, sessionMode);

    CameraStandard::FocusTrackingMetaInfo info;
    // Use negative trackingObjectId to exercise fallback paths in GetTrackingTarget
    info.SetTrackingObjectId(fdp.ConsumeIntegralInRange<int32_t>(MIN_INVALID_OBJECT_ID, MAX_INVALID_OBJECT_ID));

    CameraStandard::Rect trackingRegion = GenerateRandomRect(fdp);
    info.SetTrackingRegion(trackingRegion);

    int32_t trackingMode = fdp.ConsumeIntegralInRange<int32_t>(MIN_TRACKING_MODE, MAX_TRACKING_MODE);
    info.SetTrackingMode(static_cast<CameraStandard::FocusTrackingMode>(trackingMode));

    // Empty detected objects - exercise the empty path
    if (fdp.ConsumeBool()) {
        std::vector<sptr<CameraStandard::MetadataObject>> emptyObjects;
        info.SetDetectedObjects(emptyObjects);
    } else {
        // Objects without matching ID - exercise GetTrackingTargetFallback
        std::vector<sptr<CameraStandard::MetadataObject>> objects;
        // MetadataObjectFactory derives from RefBase; its SetXxx() methods return
        // sptr<MetadataObjectFactory>(this). Holding the factory via std::unique_ptr
        // would let the temporary sptr returned by the first setter drop the
        // refcount to 0 and delete the object, leaving the unique_ptr dangling.
        // Use sptr to share the refcount so the object stays alive across setters.
        auto factory = OHOS::sptr<CameraStandard::MetadataObjectFactory>(new CameraStandard::MetadataObjectFactory());
        CameraStandard::Rect box = GenerateRandomRect(fdp);
        factory->SetBox(box);
        factory->SetObjectId(fdp.ConsumeIntegralInRange<int32_t>(MIN_METADATA_OBJECT_ID, MAX_METADATA_OBJECT_ID));
        factory->SetConfidence(fdp.ConsumeIntegral<int32_t>());
        factory->SetIsLockFocusTracked(fdp.ConsumeBool());
        factory->SetTimestamp(0);
        int32_t objType = fdp.ConsumeIntegralInRange<int32_t>(MIN_OBJECT_TYPE, MAX_OBJECT_TYPE);
        objects.push_back(
            factory->createMetadataObject(static_cast<CameraStandard::MetadataObjectType>(objType)));
        info.SetDetectedObjects(objects);
    }

    g_cameraTrackingController->OnFocusTracking(info);
}

// Fuzz OnMetadataInfo with CameraMetadata containing FOV tag
void FuzzOnMetadataInfoWithFov(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    InitCameraTrackingController();
    if (!IsControllerValid()) {
        return;
    }

    // Setup camera session first
    SetupCaptureSessionInfo(fdp, static_cast<int32_t>(CameraStandard::SceneMode::NORMAL));

    bool passNull = fdp.ConsumeBool();
    if (passNull) {
        g_cameraTrackingController->OnMetadataInfo(nullptr);
        return;
    }

    size_t itemCapacity = fdp.ConsumeIntegralInRange<size_t>(MIN_ITEM_CAPACITY, MAX_ITEM_CAPACITY);
    size_t dataCapacity = fdp.ConsumeIntegralInRange<size_t>(MIN_DATA_CAPACITY, MAX_DATA_CAPACITY);
    auto metadata = std::make_shared<OHOS::Camera::CameraMetadata>(itemCapacity, dataCapacity);

    bool addFovTag = fdp.ConsumeBool();
    if (addFovTag) {
        // Add FOV info tag with 2 float values to exercise the FOV extraction path
        float fovData[FOV_VALUE_COUNT] = {
            fdp.ConsumeFloatingPoint<float>(),
            fdp.ConsumeFloatingPoint<float>()
        };
        metadata->addEntry(OHOS_STATUS_FOV_INFOS, fovData, FOV_VALUE_COUNT);
    }

    g_cameraTrackingController->OnMetadataInfo(metadata);
}

// Fuzz OnZoomInfoChange with valid zoom values
void FuzzOnZoomInfoChangeWithSession(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    InitCameraTrackingController();
    if (!IsControllerValid()) {
        return;
    }

    // Setup camera session first so currentCameraInfo_ has valid tokenId
    SetupCaptureSessionInfo(fdp, static_cast<int32_t>(CameraStandard::SceneMode::VIDEO));

    int32_t sessionid = fdp.ConsumeIntegral<int32_t>();
    CameraStandard::ZoomInfo zoomInfo;
    zoomInfo.zoomValue = fdp.ConsumeFloatingPointInRange<float>(0.1f, 20.0f);
    zoomInfo.equivalentFocus = fdp.ConsumeIntegralInRange<int32_t>(MIN_EQUIVALENT_FOCUS, MAX_EQUIVALENT_FOCUS);
    zoomInfo.videoStabilizationMode = fdp.ConsumeIntegralInRange<int32_t>(MIN_MODE_INDEX, MAX_MODE_INDEX);
    zoomInfo.focusMode = fdp.ConsumeIntegralInRange<int32_t>(MIN_FOCUS_MODE, MAX_FOCUS_MODE);

    g_cameraTrackingController->OnZoomInfoChange(sessionid, zoomInfo);
}

// Fuzz OnSessionStatusChange with both true and false status
void FuzzOnSessionStatusChangeWithSession(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    InitCameraTrackingController();
    if (!IsControllerValid()) {
        return;
    }

    // Setup camera session first
    SetupCaptureSessionInfo(fdp, static_cast<int32_t>(CameraStandard::SceneMode::VIDEO));

    int32_t sessionid = fdp.ConsumeIntegral<int32_t>();
    bool status = fdp.ConsumeBool();
    g_cameraTrackingController->OnSessionStatusChange(sessionid, status);

    // Toggle to exercise both branches (status true then false)
    if (fdp.ConsumeBool()) {
        g_cameraTrackingController->OnSessionStatusChange(sessionid, !status);
    }
}

// Fuzz UpdateCurrentCameraInfoByCaptureSessionInfo indirectly through OnCaptureSessionConfiged
// with different positions (front/back camera) and session modes
void FuzzUpdateCurrentCameraInfo(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    InitCameraTrackingController();
    if (!IsControllerValid()) {
        return;
    }

    CameraStandard::CaptureSessionInfo captureSessionInfo;

    // Build output infos
    CameraStandard::OutputInfo videoOutputInfo;
    videoOutputInfo.type = CameraStandard::OutputType::VIDEO;
    videoOutputInfo.width = fdp.ConsumeIntegralInRange<int32_t>(MIN_STREAM_RESOLUTION, MAX_STREAM_RESOLUTION);
    videoOutputInfo.height = fdp.ConsumeIntegralInRange<int32_t>(MIN_STREAM_RESOLUTION, MAX_STREAM_RESOLUTION);
    captureSessionInfo.outputInfos.push_back(videoOutputInfo);

    CameraStandard::OutputInfo previewOutputInfo;
    previewOutputInfo.type = CameraStandard::OutputType::PREVIEW;
    previewOutputInfo.width = fdp.ConsumeIntegralInRange<int32_t>(MIN_STREAM_RESOLUTION, MAX_STREAM_RESOLUTION);
    previewOutputInfo.height = fdp.ConsumeIntegralInRange<int32_t>(MIN_STREAM_RESOLUTION, MAX_STREAM_RESOLUTION);
    captureSessionInfo.outputInfos.push_back(previewOutputInfo);

    // Use specific scene modes for different sessionMode paths
    int32_t sceneModes[] = {
        static_cast<int32_t>(CameraStandard::SceneMode::NORMAL),
        static_cast<int32_t>(CameraStandard::SceneMode::CAPTURE),
        static_cast<int32_t>(CameraStandard::SceneMode::VIDEO),
        static_cast<int32_t>(CameraStandard::SceneMode::PORTRAIT),
        static_cast<int32_t>(CameraStandard::SceneMode::CINEMATIC_VIDEO),
    };
    int32_t modeIndex = fdp.ConsumeIntegralInRange<int32_t>(MIN_MODE_INDEX, MAX_MODE_INDEX);
    captureSessionInfo.sessionMode = sceneModes[modeIndex];

    captureSessionInfo.callerTokenId = 0;
    captureSessionInfo.sessionId = fdp.ConsumeIntegral<int32_t>();
    captureSessionInfo.position = fdp.ConsumeBool() ? REAR_MOUNTED_LENS : 0;
    captureSessionInfo.zoomInfo.zoomValue = fdp.ConsumeFloatingPointInRange<float>(0.5f, 10.0f);
    captureSessionInfo.zoomInfo.equivalentFocus =
        fdp.ConsumeIntegralInRange<int32_t>(MIN_EQUIVALENT_FOCUS, MAX_EQUIVALENT_FOCUS);
    captureSessionInfo.zoomInfo.videoStabilizationMode =
        fdp.ConsumeIntegralInRange<int32_t>(MIN_MODE_INDEX, MAX_MODE_INDEX);
    captureSessionInfo.zoomInfo.focusMode = fdp.ConsumeIntegral<int32_t>();
    captureSessionInfo.sessionStatus = fdp.ConsumeBool();

    g_cameraTrackingController->OnCaptureSessionConfiged(captureSessionInfo);

    // Call again with different camera position to trigger front/back switch
    if (fdp.ConsumeBool()) {
        captureSessionInfo.position = (captureSessionInfo.position == REAR_MOUNTED_LENS) ? 0 : REAR_MOUNTED_LENS;
        captureSessionInfo.sessionMode =
            sceneModes[fdp.ConsumeIntegralInRange<int32_t>(MIN_MODE_INDEX, MAX_MODE_INDEX)];
        g_cameraTrackingController->OnCaptureSessionConfiged(captureSessionInfo);
    }
}

// Fuzz ComputeFov indirectly by varying zoom and video stabilization modes
void FuzzComputeFovVariants(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    InitCameraTrackingController();
    if (!IsControllerValid()) {
        return;
    }

    // Test different video stabilization modes to exercise SensorCutForVideoMode branches
    int32_t stabModes[] = {
        static_cast<int32_t>(StabMode::OHOS_CAMERA_VIDEO_STABILIZATION_OFF),
        static_cast<int32_t>(StabMode::OHOS_CAMERA_VIDEO_STABILIZATION_LOW),
        static_cast<int32_t>(StabMode::OHOS_CAMERA_VIDEO_STABILIZATION_MIDDLE),
        static_cast<int32_t>(StabMode::OHOS_CAMERA_VIDEO_STABILIZATION_HIGH),
        static_cast<int32_t>(StabMode::OHOS_CAMERA_VIDEO_STABILIZATION_AUTO),
    };

    CameraStandard::CaptureSessionInfo captureSessionInfo;
    CameraStandard::OutputInfo videoOutputInfo;
    videoOutputInfo.type = CameraStandard::OutputType::VIDEO;
    videoOutputInfo.width = fdp.ConsumeIntegralInRange<int32_t>(MIN_STREAM_RESOLUTION, MAX_STREAM_RESOLUTION);
    videoOutputInfo.height = fdp.ConsumeIntegralInRange<int32_t>(MIN_STREAM_RESOLUTION, MAX_STREAM_RESOLUTION);
    captureSessionInfo.outputInfos.push_back(videoOutputInfo);

    captureSessionInfo.callerTokenId = 0;
    captureSessionInfo.sessionId = fdp.ConsumeIntegral<int32_t>();
    captureSessionInfo.position = fdp.ConsumeBool() ? REAR_MOUNTED_LENS : 0;

    int32_t modeIndex = fdp.ConsumeIntegralInRange<int32_t>(MIN_MODE_INDEX, MAX_MODE_INDEX);
    captureSessionInfo.sessionMode = (modeIndex <= 1)
        ? static_cast<int32_t>(CameraStandard::SceneMode::VIDEO)
        : static_cast<int32_t>(CameraStandard::SceneMode::CINEMATIC_VIDEO);

    int32_t stabIndex = fdp.ConsumeIntegralInRange<int32_t>(MIN_MODE_INDEX, MAX_MODE_INDEX);
    captureSessionInfo.zoomInfo.zoomValue = fdp.ConsumeFloatingPointInRange<float>(0.5f, 10.0f);
    captureSessionInfo.zoomInfo.equivalentFocus =
        fdp.ConsumeIntegralInRange<int32_t>(MIN_EQUIVALENT_FOCUS, MAX_EQUIVALENT_FOCUS);
    captureSessionInfo.zoomInfo.videoStabilizationMode = stabModes[stabIndex];
    captureSessionInfo.zoomInfo.focusMode = 1;
    captureSessionInfo.sessionStatus = true;

    g_cameraTrackingController->OnCaptureSessionConfiged(captureSessionInfo);
}

// Fuzz CalculateIOU indirectly through OnFocusTracking with overlapping rects
void FuzzCalculateIOUViaTracking(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    InitCameraTrackingController();
    if (!IsControllerValid()) {
        return;
    }

    int32_t sessionMode = fdp.ConsumeIntegralInRange<int32_t>(MIN_SCENE_MODE, MAX_SCENE_MODE);
    SetupCaptureSessionInfo(fdp, sessionMode);

    // Create two FocusTrackingMetaInfo calls with overlapping rects to exercise
    // IOU calculation in IsAllowedConversion and CalculateIOU
    for (int32_t iter = 0; iter < OBJECT_PAIR_COUNT; iter++) {
        CameraStandard::FocusTrackingMetaInfo info;
        info.SetTrackingObjectId(fdp.ConsumeIntegralInRange<int32_t>(MIN_TRACKING_OBJECT_ID, MAX_TRACKING_OBJECT_ID));

        CameraStandard::Rect trackingRegion = GenerateRandomRect(fdp);
        info.SetTrackingRegion(trackingRegion);

        int32_t trackingMode = fdp.ConsumeIntegralInRange<int32_t>(MIN_TRACKING_MODE, MAX_TRACKING_MODE);
        info.SetTrackingMode(static_cast<CameraStandard::FocusTrackingMode>(trackingMode));

        // Create overlapping objects to exercise CalculateIOU paths
        std::vector<sptr<CameraStandard::MetadataObject>> objects;
        CameraStandard::Rect baseRect = GenerateRandomRect(fdp);

        // Create a face object with the base rect
        auto faceFactory =
            OHOS::sptr<CameraStandard::MetadataObjectFactory>(new CameraStandard::MetadataObjectFactory());
        faceFactory->SetBox(baseRect);
        faceFactory->SetObjectId(0);
        faceFactory->SetConfidence(CONFIDENCE_VERY_HIGH);
        faceFactory->SetIsLockFocusTracked(false);
        faceFactory->SetTimestamp(0);
        objects.push_back(faceFactory->createMetadataObject(CameraStandard::MetadataObjectType::FACE));

        // Create another face with overlapping rect for IOU > threshold
        if (fdp.ConsumeBool()) {
            auto faceFactory2 =
                OHOS::sptr<CameraStandard::MetadataObjectFactory>(new CameraStandard::MetadataObjectFactory());
            CameraStandard::Rect overlapRect;
            // Make overlapping rect by using similar coordinates
            overlapRect.topLeftX = baseRect.topLeftX +
                fdp.ConsumeFloatingPointInRange<double>(-OVERLAP_RECT_DELTA, OVERLAP_RECT_DELTA);
            overlapRect.topLeftY = baseRect.topLeftY +
                fdp.ConsumeFloatingPointInRange<double>(-OVERLAP_RECT_DELTA, OVERLAP_RECT_DELTA);
            overlapRect.width = baseRect.width +
                fdp.ConsumeFloatingPointInRange<double>(-OVERLAP_RECT_DELTA, OVERLAP_RECT_DELTA);
            overlapRect.height = baseRect.height +
                fdp.ConsumeFloatingPointInRange<double>(-OVERLAP_RECT_DELTA, OVERLAP_RECT_DELTA);
            faceFactory2->SetBox(overlapRect);
            faceFactory2->SetObjectId(1);
            faceFactory2->SetConfidence(CONFIDENCE_MEDIUM);
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
    FuzzedDataProvider fdp(data, size);
    InitCameraTrackingController();
    if (!IsControllerValid()) {
        return;
    }

    // Must use CINEMATIC_VIDEO mode
    SetupCaptureSessionInfo(fdp, static_cast<int32_t>(CameraStandard::SceneMode::CINEMATIC_VIDEO));

    // First call with SALIENT_DETECTION + isLockFocusTracked=true to set isSalientDetectionLocked_
    CameraStandard::FocusTrackingMetaInfo info1;
    info1.SetTrackingObjectId(
        fdp.ConsumeIntegralInRange<int32_t>(MIN_TRACKING_OBJECT_ID, MAX_TRACKING_OBJECT_ID));
    info1.SetTrackingRegion(GenerateRandomRect(fdp));
    info1.SetTrackingMode(CameraStandard::FocusTrackingMode::FOCUS_TRACKING_MODE_AUTO);

    std::vector<sptr<CameraStandard::MetadataObject>> objects1;
    objects1.push_back(CreateObject(fdp, CameraStandard::MetadataObjectType::SALIENT_DETECTION, 0,
        CONFIDENCE_MEDIUM, true));
    info1.SetDetectedObjects(objects1);
    g_cameraTrackingController->OnFocusTracking(info1);

    // Second call with different target to exercise CinematicVideoModeTrackingTargetFilter
    CameraStandard::FocusTrackingMetaInfo info2;
    info2.SetTrackingObjectId(
        fdp.ConsumeIntegralInRange<int32_t>(MIN_TRACKING_OBJECT_ID, MAX_TRACKING_OBJECT_ID));
    info2.SetTrackingRegion(GenerateRandomRect(fdp));
    info2.SetTrackingMode(static_cast<CameraStandard::FocusTrackingMode>(
        fdp.ConsumeIntegralInRange<int32_t>(MIN_TRACKING_MODE, MAX_TRACKING_MODE)));

    std::vector<sptr<CameraStandard::MetadataObject>> objects2;
    objects2.push_back(CreateObject(fdp, CameraStandard::MetadataObjectType::HUMAN_BODY, 1,
        CONFIDENCE_HIGH, false));
    objects2.push_back(CreateFaceObject(fdp, GenerateRandomRect(fdp), HEAD_OBJECT_ID, CONFIDENCE_MEDIUM));
    objects2.push_back(CreateObject(fdp, CameraStandard::MetadataObjectType::HUMAN_HEAD, SALIENT_OBJECT_ID,
        CONFIDENCE_FAIR, false));

    info2.SetDetectedObjects(objects2);
    g_cameraTrackingController->OnFocusTracking(info2);
}

} // namespace

namespace {
struct ControllerCleaner {
    ~ControllerCleaner()
    {
        // When the fuzz process exits, all pending tasks on eventHandler_ are
        // removed before the McCameraTrackingController singleton is destructed.
        // This prevents heap-use-after-free when the background EventRunner tries
        // to execute lambdas that capture `this`.
        CleanupCameraTrackingController();
    }
};
const ControllerCleaner g_controllerCleaner;
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    uint8_t funcIndex = fdp.ConsumeIntegral<uint8_t>() % FUZZ_FUNC_COUNT;
    auto remaining = fdp.ConsumeRemainingBytes<uint8_t>();
    const uint8_t *funcData = remaining.data();
    size_t funcSize = remaining.size();

    if (funcIndex < FUZZ_FUNC_COUNT) {
        FUZZ_FUNCS[funcIndex](funcData, funcSize);
    }
    return 0;
}
