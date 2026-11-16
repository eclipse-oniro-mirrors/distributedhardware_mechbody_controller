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
 
#include "mc_camera_tracking_controller.h"
#include "mechbody_controller_service.h"
#include "mechbody_controller_log.h"
 
namespace OHOS {
namespace MechBodyController {
namespace {
    const std::string TAG = "McCameraAutoCenterController";
    constexpr int32_t AUTO_CENTER_DELAY = 30000; // 30s
    constexpr int32_t AUTO_CENTER_CHECKER_INTERVAL = 1000; // 1s
    constexpr int32_t SYSTEM_INNER_TOKEN_ID = 0;
}
 
void McCameraTrackingController::AutoCenterChecker()
{
    HILOGI("AutoCenterChecker thread started");
    while (startAutoCenterChecker_.load()) {
        if (!isAutoCentering_.load()) {
            PerformAutoCenter();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(AUTO_CENTER_CHECKER_INTERVAL));
    }
    HILOGI("AutoCenterChecker thread stopped");
}
 
void McCameraTrackingController::PerformAutoCenter()
{
    if (!IsCurrentTrackingEnabled()) {
        return;
    }
    int64_t frameTimeNs = lastTrackingFrameTimeNs_.load();
    if (frameTimeNs <= 0) {
        return;
    }
    auto frameTime = std::chrono::steady_clock::time_point(
        std::chrono::steady_clock::duration(frameTimeNs));
    auto timeDiff = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - frameTime).count();
    if (timeDiff < AUTO_CENTER_DELAY) {
        return;
    }
    HILOGD("Auto center triggered after target lost for %{public}lld ms.", timeDiff);
    isAutoCentering_.store(true);
    std::lock_guard<std::mutex> lock(MechBodyControllerService::GetInstance().motionManagersMutex);
    for (const auto &item : MechBodyControllerService::GetInstance().motionManagers_) {
        int32_t mechId = item.first;
        std::shared_ptr<MotionManager> motionManager = item.second;
        if (motionManager == nullptr) {
            HILOGE("MotionManager not exists; mechId: %{public}d", mechId);
            continue;
        }
        std::string emptyCmdId;
        int32_t result = motionManager->DoAction(SYSTEM_INNER_TOKEN_ID, emptyCmdId, ActionType::HEAD_TURN_TO_BASE);
        HILOGD("Auto center DoAction result: %{public}d, mechId: %{public}d", result, mechId);
    }
}

void McCameraTrackingController::RefreshAutoCenterTimer()
{
    lastTrackingFrameTimeNs_.store(std::chrono::steady_clock::now().time_since_epoch().count());
}
 
} // namespace MechBodyController
} // namespace OHOS