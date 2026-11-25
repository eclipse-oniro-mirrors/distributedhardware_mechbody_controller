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
#include "mccameratrackingcontrollerseven_fuzzer.h"
#include "mc_camera_tracking_controller.h"
#include "mechbody_controller_service.h"
#include "mechbody_controller_types.h"
#include "mechbody_controller_enums.h"
#include <cstdlib>
#include <memory>
#include <mutex>

using namespace OHOS;
using namespace OHOS::MechBodyController;

namespace {

constexpr uint32_t MIN_CALL_COUNT = 1;
constexpr uint32_t MAX_CALL_COUNT = 5;
constexpr int32_t MIN_MOBILE_ROTATION = -1;
constexpr int32_t MAX_MOBILE_ROTATION = 270;

McCameraTrackingController* g_cameraTrackingController = nullptr;
std::once_flag g_initOnceFlag;
bool g_initialized = false;

void CleanupCameraTrackingController()
{
    if (g_cameraTrackingController != nullptr && g_initialized) {
        g_cameraTrackingController->UnInit();
        g_initialized = false;
    }
}

void InitCameraTrackingController()
{
    if (g_cameraTrackingController == nullptr) {
        g_cameraTrackingController = &McCameraTrackingController::GetInstance();
    }
    std::call_once(g_initOnceFlag, []() {
        g_cameraTrackingController->Init();
        g_initialized = true;
    });
}

void FuzzRefreshAutoCenterTimer(FuzzedDataProvider &provider)
{
    InitCameraTrackingController();
    uint32_t refreshCount = provider.ConsumeIntegralInRange<uint32_t>(MIN_CALL_COUNT, MAX_CALL_COUNT);
    for (uint32_t i = 0; i < refreshCount; i++) {
        g_cameraTrackingController->RefreshAutoCenterTimer();
    }
}

void FuzzUpdateScreenInfo(FuzzedDataProvider &provider)
{
    InitCameraTrackingController();
    int32_t rotationRaw = provider.ConsumeIntegralInRange<int32_t>(MIN_MOBILE_ROTATION, MAX_MOBILE_ROTATION);
    MobileRotation rotation = static_cast<MobileRotation>(rotationRaw);
    g_cameraTrackingController->UpdateScreenInfo(rotation);
}

void FuzzHandleCameraDisabledChangeCallback(FuzzedDataProvider &provider)
{
    InitCameraTrackingController();
    bool isCameraDisabled = provider.ConsumeBool();
    // HandleCameraDisabledChangeCallback is not available on this branch
    (void)isCameraDisabled;
}

void FuzzUpdateActionControl(FuzzedDataProvider &provider)
{
    InitCameraTrackingController();
    uint32_t callCount = provider.ConsumeIntegralInRange<uint32_t>(MIN_CALL_COUNT, MAX_CALL_COUNT);
    for (uint32_t i = 0; i < callCount; i++) {
        g_cameraTrackingController->UpdateActionControl();
    }
}

void FuzzSearchTargetStop(FuzzedDataProvider &provider)
{
    InitCameraTrackingController();
    uint32_t callCount = provider.ConsumeIntegralInRange<uint32_t>(MIN_CALL_COUNT, MAX_CALL_COUNT);
    for (uint32_t i = 0; i < callCount; i++) {
        g_cameraTrackingController->SearchTargetStop();
    }
}

void FuzzSearchTargetRotateFinish(FuzzedDataProvider &provider)
{
    InitCameraTrackingController();
    std::string cmdId = provider.ConsumeRandomLengthString(64);
    g_cameraTrackingController->SearchTargetRotateFinish(cmdId);
}
} // namespace

namespace {
struct ControllerCleaner {
    ~ControllerCleaner()
    {
        CleanupCameraTrackingController();
    }
};
const ControllerCleaner CONTROLLER_CLEANER;
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return 0;
    }
    FuzzedDataProvider provider(data, size);
    FuzzRefreshAutoCenterTimer(provider);
    FuzzUpdateScreenInfo(provider);
    FuzzHandleCameraDisabledChangeCallback(provider);
    FuzzUpdateActionControl(provider);
    FuzzSearchTargetStop(provider);
    FuzzSearchTargetRotateFinish(provider);
    return 0;
}
