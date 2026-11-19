/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
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
 
#include "ani_mech_manager.h"
 
#include <algorithm>
#include <memory>
#include <utility>
#include <vector>
 
#include "mechbody_controller_log.h"
 
namespace OHOS {
namespace MechBodyController {
namespace {
    const std::string TAG = "AniMechManager";
}
 
void AniMechManager::OnBatteryLevelChange(int32_t mechId, const BatteryLevelCBTaihe &callback)
{
    if (CheckEmulator()) {
        return;
    }
    if (CheckDeviceL1()) {
        return;
    }
    int32_t result = ExecuteOnBatteryLevelChange(mechId, callback);
    ProcessOnResultCode(result);
}
 
void AniMechManager::OffBatteryLevelChange(int32_t mechId, const ::taihe::optional_view<BatteryLevelCBTaihe> &callback)
{
    if (CheckEmulator()) {
        return;
    }
    if (CheckDeviceL1()) {
        return;
    }
    int32_t result = ExecuteOffBatteryLevelChange(mechId, callback);
    ProcessOffResultCode(result);
}
 
int32_t AniMechManager::ExecuteOnBatteryLevelChange(int32_t mechId, const BatteryLevelCBTaihe &callback)
{
    HILOGI("enter, mechId: %{public}d", mechId);
    if (callback.is_error()) {
        HILOGE("Callback error");
        return MechNapiErrorCode::PARAMETER_CHECK_FAILED;
    }
    if (!InitMechClient()) {
        HILOGE("Init Mech Client failed.");
        return SYSTEM_WORK_ABNORMALLY;
    }
    if (!InitBatteryLevelStub()) {
        return SYSTEM_WORK_ABNORMALLY;
    }
    {
        std::lock_guard<std::mutex> lock(batteryLevelCallbackMutex_);
        batteryLevelCallback_[mechId].push_back(callback);
        HILOGI("battery callback added, mechId: %{public}d, callback count: %{public}zu",
            mechId, batteryLevelCallback_[mechId].size());
    }
    int32_t registerResult = mechClient_->RegisterBatteryChannel(batteryLevelStub_, mechId);
    HILOGI("RegisterBatteryChannel result: %{public}d, mechId: %{public}d", registerResult, mechId);
    if (registerResult != ERR_OK) {
        HILOGE("RegisterBatteryChannel failed.");
        std::lock_guard<std::mutex> lock(batteryLevelCallbackMutex_);
        auto &vec = batteryLevelCallback_[mechId];
        auto it = std::find(vec.begin(), vec.end(), callback);
        if (it != vec.end()) {
            vec.erase(it);
        }
        if (vec.empty()) {
            batteryLevelCallback_.erase(mechId);
        }
        return registerResult;
    }
    return registerResult;
}
 
int32_t AniMechManager::ExecuteOffBatteryLevelChange(
    int32_t mechId, const ::taihe::optional_view<BatteryLevelCBTaihe> &callback)
{
    HILOGI("enter, mechId: %{public}d", mechId);
    if (!InitMechClient()) {
        HILOGE("Init Mech Client failed.");
        return SYSTEM_WORK_ABNORMALLY;
    }
    bool shouldUnRegisterChannel = false;
    {
        std::lock_guard<std::mutex> lock(batteryLevelCallbackMutex_);
        auto it = batteryLevelCallback_.find(mechId);
        if (it == batteryLevelCallback_.end()) {
            HILOGI("No battery callback found for mechId: %{public}d", mechId);
            return ERR_OK;
        }
        if (callback.has_value()) {
            BatteryLevelCBTaihe cb = callback.value();
            auto &vec = it->second;
            vec.erase(std::remove_if(vec.begin(), vec.end(),
                [&cb](const BatteryLevelCBTaihe &item) {
                    return item == cb;
                }), vec.end());
            if (vec.empty()) {
                batteryLevelCallback_.erase(it);
                shouldUnRegisterChannel = true;
            }
        } else {
            batteryLevelCallback_.erase(it);
            shouldUnRegisterChannel = true;
        }
    }
    int32_t registerResult = ERR_OK;
    if (shouldUnRegisterChannel) {
        registerResult = mechClient_->UnRegisterBatteryChannel();
        HILOGI("UnRegisterBatteryChannel result: %{public}d, mechId: %{public}d", registerResult, mechId);
    } else {
        HILOGI("skip UnRegisterBatteryChannel, still has callbacks for mechId: %{public}d", mechId);
    }
    return registerResult;
}
 
bool AniMechManager::InitBatteryLevelStub()
{
    if (batteryLevelStub_ != nullptr) {
        return true;
    }
    std::lock_guard<std::mutex> lock(batteryLevelStubMutex_);
    if (batteryLevelStub_ != nullptr) {
        return true;
    }
    if (!InitMechClient()) {
        return false;
    }
    sptr<AniMechManagerStub> stub = new (std::nothrow) AniMechManagerStub();
    if (stub == nullptr) {
        HILOGE("Failed to create AniMechManagerStub");
        return false;
    }
    sptr<IRemoteObject::DeathRecipient> deathListener = new AniBatteryLevelStubDeathListener();
    stub->SetDeathRecipient(deathListener);
    batteryLevelStub_ = stub;
    return batteryLevelStub_ != nullptr;
}
 
int32_t AniMechManager::BatteryLevelChangeCallbackInvoke(
    const int32_t &mechId, const int32_t &batteryLevel, const bool &isCharging)
{
    HILOGI("start. mechId: %{public}d, batteryLevel: %{public}d, isCharging: %{public}d",
        mechId, batteryLevel, isCharging);
    std::vector<BatteryLevelCBTaihe> callbackList;
    {
        std::lock_guard<std::mutex> lock(batteryLevelCallbackMutex_);
        auto it = batteryLevelCallback_.find(mechId);
        if (it == batteryLevelCallback_.end()) {
            HILOGI("No battery callback found for mechId: %{public}d", mechId);
            return ERR_OK;
        }
        callbackList = it->second;
    }
    HILOGI("battery callback count for mechId %{public}d: %{public}zu", mechId, callbackList.size());
    for (const auto &callback : callbackList) {
        auto task = [this, callback, mechId, batteryLevel, isCharging]() {
            BatteryLevelInfoTaihe taiheItem {
                .mechId = mechId,
                .batteryLevel = batteryLevel,
                .isCharging = isCharging,
            };
            callback(taiheItem);
        };
        AniSendEvent(task);
    }
    return ERR_OK;
}
 
void AniMechManager::AniBatteryLevelStubDeathListener::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    HILOGE("BatteryLevelStub RemoteObject dead; ");
    auto &instance = AniMechManager::GetInstance();
    {
        std::lock_guard<std::mutex> lock(instance.batteryLevelStubMutex_);
        instance.batteryLevelStub_ = nullptr;
    }
    std::lock_guard<std::mutex> cbLock(instance.batteryLevelCallbackMutex_);
    instance.batteryLevelCallback_.clear();
}
 
} // namespace MechBodyController
} // namespace OHOS