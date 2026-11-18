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

#include <memory>
#include "load_mechbody_adapter.h"
#include "mc_camera_tracking_controller.h"
#include "mechbody_controller_service.h"

namespace OHOS {
namespace MechBodyController {
namespace {
    const std::string TAG = "McCameraTrackingController";
    constexpr float TRACKING_LOST_CHECK = 0.0001f;
    constexpr float IOU_THRESHOLD = 0.1f;
    constexpr float IOU_DEFAULT = 0.0f;
}

int32_t McCameraTrackingController::GetTrackingTarget(CameraStandard::Rect &trackingRegion,
    std::vector<sptr<CameraStandard::MetadataObject>> &detectedObjects, int32_t trackingObjectId,
    sptr<CameraStandard::MetadataObject> &targetObject)
{
    if (detectedObjects.empty()) {
        HILOGW("detectedObjects is empty!!!");
        return DETECTED_OBJECT_IS_EMPTY;
    }
    sptr<CameraStandard::MetadataObject> selectedObject = nullptr;
    if (trackingObjectId >= 0) {
        for (const auto &item : detectedObjects) {
            if (item->GetObjectId() == trackingObjectId) {
                HILOGI("got detected object for id: %{public}d, type: %{public}d",
                    trackingObjectId, static_cast<int>(item->GetType()));
                selectedObject = item;
                break;
            }
        }
    }
    if (selectedObject != nullptr) {
        return ProcessTargetByType(selectedObject, detectedObjects, targetObject);
    }
    if (currentCameraInfo_ &&
        currentCameraInfo_->sessionMode == static_cast<int32_t>(CameraStandard::SceneMode::CINEMATIC_VIDEO) &&
        trackingObjectId >= 0) {
        HILOGW("CinematicVideo mode: trackingObjectId %{public}d not found in current frame", trackingObjectId);
        sptr<CameraStandard::MetadataObject> matchedObj = SelectBestObjectByRegion(trackingRegion, detectedObjects);
        if (matchedObj != nullptr) {
            return ProcessTargetByType(matchedObj, detectedObjects, targetObject);
        }
    }
    return GetTrackingTargetFallback(trackingRegion, detectedObjects, targetObject);
}

sptr<CameraStandard::MetadataObject> McCameraTrackingController::SelectBestObjectByRegion(
    const CameraStandard::Rect& trackingRegion,
    const std::vector<sptr<CameraStandard::MetadataObject>>& detectedObjects)
{
    sptr<CameraStandard::MetadataObject> bestObject = nullptr;
    float bestIou = IOU_THRESHOLD;
    for (const auto& obj : detectedObjects) {
        auto type = obj->GetType();
        if (type == CameraStandard::MetadataObjectType::FACE ||
            type == CameraStandard::MetadataObjectType::BASE_FACE_DETECTION ||
            type == CameraStandard::MetadataObjectType::HUMAN_HEAD) {
            float iou = CalculateIOU(trackingRegion, obj->GetBoundingBox());
            if (iou > bestIou) {
                bestIou = iou;
                bestObject = obj;
            }
        }
    }
    if (bestObject != nullptr) {
        HILOGI("SelectBestObjectByRegion: found object id=%{public}d, type=%{public}d, IOU=%{public}f",
               bestObject->GetObjectId(), static_cast<int>(bestObject->GetType()), bestIou);
    }
    return bestObject;
}

int32_t McCameraTrackingController::ProcessTargetByType(
    const sptr<CameraStandard::MetadataObject> &selectedObject,
    const std::vector<sptr<CameraStandard::MetadataObject>> &detectedObjects,
    sptr<CameraStandard::MetadataObject> &targetObject)
{
    CameraStandard::MetadataObjectType selectedType = selectedObject->GetType();
        switch (selectedType) {
            case CameraStandard::MetadataObjectType::HUMAN_HEAD:
                targetObject = FindFaceForHead(*selectedObject, detectedObjects);
                if (targetObject != nullptr) {
                    HILOGI("Tracking matching face for head.ObjectId:%{public}d ", targetObject->GetObjectId());
                    return ERR_OK;
                }
                targetObject = selectedObject;
                HILOGI("Tracking head (no matching face found)");
                return ERR_OK;
            case CameraStandard::MetadataObjectType::HUMAN_BODY:
                targetObject = FindBestFaceOrHeadForBody(*selectedObject, detectedObjects);
                if (targetObject != nullptr) {
                    HILOGI("Tracking %{public}s for body, objectID:%{public}d",
                        targetObject->GetType() == (CameraStandard::MetadataObjectType::HUMAN_HEAD)
                            ? "head"
                            : "face", targetObject->GetObjectId());
                    return ERR_OK;
                }
                targetObject = selectedObject;
                HILOGI("No matching face/head found, continue tracking body");

                return ERR_OK;
            case CameraStandard::MetadataObjectType::SALIENT_DETECTION:
                if (selectedObject->IsLockFocusTracked()) {
                    HILOGI("SALIENT_DETECTION with IsLockFocusTracked true, treat as body to find face/head");
                    targetObject = FindBestFaceOrHeadForBody(*selectedObject, detectedObjects);
                    if (targetObject != nullptr) {
                        HILOGI("Tracking %{public}s for salient detection, objectID:%{public}d",
                            targetObject->GetType() == (CameraStandard::MetadataObjectType::HUMAN_HEAD)
                                ? "head"
                                : "face", targetObject->GetObjectId());
                        return ERR_OK;
                    }
                    targetObject = selectedObject;
                    HILOGI("No matching face/head found for salient detection, continue tracking salient detection");
                    return ERR_OK;
                }
                targetObject = selectedObject;
                HILOGI("Tracking salient detection (IsLockFocusTracked is false)");
                return ERR_OK;
            default:
                targetObject = selectedObject;
                HILOGW("Tracking face/unknown type: %{public}d", static_cast<int>(selectedType));
                return ERR_OK;
        }
}

sptr<CameraStandard::MetadataObject> McCameraTrackingController::FindFaceForHead(
    CameraStandard::MetadataObject& headObject,
    const std::vector<sptr<CameraStandard::MetadataObject>>& detectedObjects)
{
    CameraStandard::Rect headRect = headObject.GetBoundingBox();
    sptr<CameraStandard::MetadataObject> bestFace = nullptr;
    float bestIou = 0.0f;

    for (const auto& obj : detectedObjects) {
        if (obj->GetType() != CameraStandard::MetadataObjectType::FACE &&
            obj->GetType() != CameraStandard::MetadataObjectType::BASE_FACE_DETECTION) {
            continue;
        }
        float iou = CalculateIOU(headRect, obj->GetBoundingBox());
        if (iou > bestIou && iou > IOU_THRESHOLD) {
            bestIou = iou;
            bestFace = obj;
            HILOGI("FindFaceForHead objectId:%{public}d,  CalculateIOU %{public}f", obj->GetObjectId(),  iou);
        }
    }
    if (bestFace != nullptr) {
        HILOGI("Found matching face for head, IOU: %{public}f", bestIou);
    }
    return bestFace;
}

sptr<CameraStandard::MetadataObject> McCameraTrackingController::FindBestFaceOrHeadForBody(
    CameraStandard::MetadataObject &bodyObject,
    const std::vector<sptr<CameraStandard::MetadataObject>> &detectedObjects)
{
    CameraStandard::Rect bodyRect = bodyObject.GetBoundingBox();
    std::vector<sptr<CameraStandard::MetadataObject>> faces;
    std::vector<sptr<CameraStandard::MetadataObject>> heads;
    for (const auto &obj : detectedObjects) {
        CameraStandard::MetadataObjectType type = obj->GetType();
        if (type == CameraStandard::MetadataObjectType::FACE ||
            type == CameraStandard::MetadataObjectType::BASE_FACE_DETECTION) {
            faces.push_back(obj);
        } else if (type == CameraStandard::MetadataObjectType::HUMAN_HEAD) {
            heads.push_back(obj);
        }
    }
    sptr<CameraStandard::MetadataObject> bestMatch = FindBestMatchForBody(bodyRect, faces);
    if (bestMatch != nullptr) {
        HILOGI("Found matching face for body.Face ObjectId:%{public}d", bestMatch->GetObjectId());
        return bestMatch;
    }
    bestMatch = FindBestMatchForBody(bodyRect, heads);
    if (bestMatch != nullptr) {
        HILOGI("Found matching head for body.Head ObjectId:%{public}d", bestMatch->GetObjectId());
        return bestMatch;
    }
    return nullptr;
}

sptr<CameraStandard::MetadataObject> McCameraTrackingController::FindBestMatchForBody(
    const CameraStandard::Rect &bodyRect, std::vector<sptr<CameraStandard::MetadataObject>> &objectsForBody)
{
    sptr<CameraStandard::MetadataObject> bestMatch = nullptr;
    float bestIou = 0.0f;
    int matchCount = 0;
    for (const auto &object : objectsForBody) {
        float iou = CalculateIOU(bodyRect, object->GetBoundingBox());
        if (iou > IOU_THRESHOLD) {
            matchCount++;
            if (iou > bestIou) {
                bestIou = iou;
                bestMatch = object;
                HILOGI("Find MatchObject IOU For Body. objectId:%{public}d,  CalculateIOU %{public}f",
                    object->GetObjectId(),
                    iou);
            }
        }
    }
    if (matchCount > 1) {
        HILOGW("Found %{public}d matching object for body, keeping body tracking", matchCount);
        return nullptr;
    }
    return bestMatch;
}

int32_t McCameraTrackingController::GetTrackingTargetFallback(CameraStandard::Rect &trackingRegion,
    std::vector<sptr<CameraStandard::MetadataObject>> &detectedObjects,
    sptr<CameraStandard::MetadataObject> &targetObject)
{
    sptr<CameraStandard::MetadataObject> selectedObject = nullptr;

    for (const auto &item : detectedObjects) {
        if (item->GetType() == CameraStandard::MetadataObjectType::SALIENT_DETECTION && item->IsLockFocusTracked()) {
            HILOGD("found SALIENT_DETECTION with isLockFocusTracked true");
            selectedObject = item;
            isSalientDetectionLocked_.store(true, std::memory_order_relaxed);
            return ProcessTargetByType(selectedObject, detectedObjects, targetObject);
        }
    }
    isSalientDetectionLocked_.store(false, std::memory_order_relaxed);

    auto lastFrame = std::atomic_load(&lastTrackingFrame_);
    if (lastFrame != nullptr && lastFrame->targetId >= 0) {
        for (const auto &item : detectedObjects) {
            if (item->GetObjectId() == lastFrame->targetId) {
                HILOGD("got detected object for id: %{public}d", lastFrame->targetId);
                selectedObject = item;
                ProcessTargetByType(selectedObject, detectedObjects, targetObject);
                return ERR_OK;
            }
        }
    }

    for (const auto &item : detectedObjects) {
        CameraStandard::Rect itemRect = item->GetBoundingBox();
        if (std::abs(itemRect.topLeftX - trackingRegion.topLeftX) <= TRACKING_LOST_CHECK &&
            std::abs(itemRect.topLeftY - trackingRegion.topLeftY) <= TRACKING_LOST_CHECK) {
            HILOGI("got detected object which is same as trackingRegion");
            selectedObject = item;
            ProcessTargetByType(selectedObject, detectedObjects, targetObject);
            return ERR_OK;
        }
    }

    HILOGW("use first object as target object.");
    selectedObject = detectedObjects[0];
    return ProcessTargetByType(selectedObject, detectedObjects, targetObject);
}

float McCameraTrackingController::CalculateIOU(const CameraStandard::Rect &rect1, const CameraStandard::Rect &rect2)
{
    if (rect1.width <= 0 || rect1.height <= 0 || rect2.width <= 0 || rect2.height <= 0) {
        return IOU_DEFAULT;
    }
    float left1 = rect1.topLeftX;
    float top1 = rect1.topLeftY;
    float right1 = rect1.width;
    float bottom1 = rect1.height;

    float left2 = rect2.topLeftX;
    float top2 = rect2.topLeftY;
    float right2 = rect2.width;
    float bottom2 = rect2.height;
    if (right1 <= left1 || bottom1 <= top1 || right2 <= left2 || bottom2 <= top2) {
        return IOU_DEFAULT;
    }
    float interLeft = std::max(left1, left2);
    float interTop = std::max(top1, top2);
    float interRight = std::min(right1, right2);
    float interBottom = std::min(bottom1, bottom2);
    if (interRight <= interLeft || interBottom <= interTop) {
        return IOU_DEFAULT;
    }
    float interArea = (interRight - interLeft) * (interBottom - interTop);
    float area1 = (right1 - left1) * (bottom1 - top1);
    float area2 = (right2 - left2) * (bottom2 - top2);
    float minArea = std::min(area1, area2);
    if (minArea <= TRACKING_LOST_CHECK) {
        return IOU_DEFAULT;
    }
    return (minArea > 0.0f) ? (interArea / minArea) : IOU_DEFAULT;
}

bool McCameraTrackingController::IsAllowedConversion(
    CameraStandard::Rect &lastTrackingRect, CameraStandard::Rect &trackingRect)
{
    float iou = CalculateIOU(lastTrackingRect, trackingRect);
    if (iou > IOU_THRESHOLD) {
        HILOGI("Conversion allowed, IOU: %{public}f", iou);
        return true;
    } else {
        HILOGW("Conversion rejected, IOU too low: %{public}f", iou);
        return false;
    }
}
} // namespace MechBodyController
} // namespace OHOS
