/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
 
#include "mc_battery_manager.h"
 
namespace OHOS {
namespace MechBodyController {
namespace {
    const std::string TAG = "McBatteryManager";
}
 
McBatteryManager::McBatteryManager() {}
 
McBatteryManager::~McBatteryManager()
{
    UnInit();
}
 
int32_t McBatteryManager::Init(const std::string &mac, int32_t mechId, const BatteryLevelChangeCallback &callback)
{
    HILOGI("mac: %{public}s, mechId: %{public}d", GetAnonymStr(mac).c_str(), mechId);
    mac_ = mac;
    mechId_ = mechId;
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        callback_ = callback;
    }
    std::lock_guard<std::mutex> lock(observerMutex_);
    if (isObserverRegistered_) {
        return ERR_OK;
    }
    auto *basHost = Bluetooth::BluetoothBasHost::GetProfile();
    if (basHost == nullptr) {
        HILOGE("BluetoothBasHost is nullptr");
        return DEVICE_NOT_SUPPORTED;
    }
    bool isSupported = false;
    int32_t ret = basHost->IsBasSupported(isSupported);
    if (ret != Bluetooth::RET_NO_ERROR || !isSupported) {
        HILOGI("BAS is not supported, ret: %{public}d, isSupported: %{public}d", ret, isSupported);
        return DEVICE_NOT_SUPPORTED;
    }
    ret = basHost->RegisterBatteryObserver(
        std::shared_ptr<McBatteryManager>(this, [](McBatteryManager *) {}));
    if (ret != Bluetooth::RET_NO_ERROR) {
        HILOGE("RegisterBatteryObserver failed, ret: %{public}d", ret);
        return DEVICE_NOT_SUPPORTED;
    }
    isObserverRegistered_ = true;
    HILOGI("battery observer registered successfully");
    return ERR_OK;
}
 
void McBatteryManager::UnInit()
{
    HILOGI("mac: %{public}s", GetAnonymStr(mac_).c_str());
    {
        std::lock_guard<std::mutex> lock(observerMutex_);
        if (isObserverRegistered_) {
            auto *basHost = Bluetooth::BluetoothBasHost::GetProfile();
            if (basHost == nullptr) {
                HILOGE("BluetoothBasHost is nullptr");
                isObserverRegistered_ = false;
            } else {
                basHost->DeregisterBatteryObserver(
                    std::shared_ptr<McBatteryManager>(this, [](McBatteryManager *) {}));
                isObserverRegistered_ = false;
            }
        }
    }
    std::lock_guard<std::mutex> lock(stateMutex_);
    cachedBatteryLevel_ = BATTERY_LEVEL_NOT_QUERIED;
    isCharging_ = false;
}
 
bool McBatteryManager::IsObserverRegistered()
{
    std::lock_guard<std::mutex> lock(observerMutex_);
    return isObserverRegistered_;
}
 
void McBatteryManager::SetIsCharging(bool isCharging)
{
    HILOGI("SetIsCharging, isCharging: %{public}d", isCharging);
    std::lock_guard<std::mutex> lock(stateMutex_);
    isCharging_ = isCharging;
}
 
void McBatteryManager::OnGetBatteryLevelEvent(const Bluetooth::BluetoothRemoteDevice &device, int32_t batteryLevel)
{
    std::string mac = device.GetDeviceAddr();
    if (mac != mac_) {
        HILOGW("mac mismatch, ignored: %{public}s", GetAnonymStr(mac).c_str());
        return;
    }
    HILOGI("mac: %{public}s, batteryLevel: %{public}d", GetAnonymStr(mac).c_str(), batteryLevel);
    if (!IsValidBatteryLevel(batteryLevel)) {
        HILOGE("abnormal battery level: %{public}d, mac: %{public}s", batteryLevel, GetAnonymStr(mac).c_str());
        return;
    }
    CacheBatteryLevel(batteryLevel);
    NotifyBatteryLevelChange(batteryLevel);
}
 
void McBatteryManager::OnBatteryLevelChanged(const Bluetooth::BluetoothRemoteDevice &device, int32_t batteryLevel)
{
    std::string mac = device.GetDeviceAddr();
    if (mac != mac_) {
        HILOGW("mac mismatch, ignored: %{public}s", GetAnonymStr(mac).c_str());
        return;
    }
    HILOGI("mac: %{public}s, batteryLevel: %{public}d", GetAnonymStr(mac).c_str(), batteryLevel);
    if (!IsValidBatteryLevel(batteryLevel)) {
        HILOGE("abnormal battery level: %{public}d, mac: %{public}s", batteryLevel, GetAnonymStr(mac).c_str());
        return;
    }
    CacheBatteryLevel(batteryLevel);
    NotifyBatteryLevelChange(batteryLevel);
}
 
void McBatteryManager::CacheBatteryLevel(int32_t batteryLevel)
{
    std::lock_guard<std::mutex> lock(stateMutex_);
    cachedBatteryLevel_ = batteryLevel;
    HILOGI("CacheBatteryLevel, batteryLevel: %{public}d", batteryLevel);
}
 
bool McBatteryManager::IsValidBatteryLevel(int32_t batteryLevel)
{
    return batteryLevel == BATTERY_LEVEL_NOT_SUPPORTED ||
        (batteryLevel >= BATTERY_LEVEL_MIN && batteryLevel <= BATTERY_LEVEL_MAX);
}
 
int32_t McBatteryManager::GetCachedBatteryLevel()
{
    std::lock_guard<std::mutex> lock(stateMutex_);
    return cachedBatteryLevel_;
}
 
bool McBatteryManager::GetIsCharging()
{
    std::lock_guard<std::mutex> lock(stateMutex_);
    return isCharging_;
}
 
void McBatteryManager::RequestBatteryLevel()
{
    auto *basHost = Bluetooth::BluetoothBasHost::GetProfile();
    if (basHost == nullptr) {
        HILOGE("BluetoothBasHost is nullptr");
        return;
    }
    std::map<std::string, int32_t> batteryInfos;
    int32_t ret = basHost->GetConnectedDeviceBatteryInfos(batteryInfos);
    HILOGI("GetConnectedDeviceBatteryInfos ret: %{public}d, device count: %{public}zu", ret, batteryInfos.size());
    if (ret != Bluetooth::RET_NO_ERROR) {
        HILOGE("GetConnectedDeviceBatteryInfos failed, ret: %{public}d", ret);
        return;
    }
    auto it = batteryInfos.find(mac_);
    if (it == batteryInfos.end()) {
        HILOGI("device not found in battery infos, mac: %{public}s", GetAnonymStr(mac_).c_str());
        return;
    }
    int32_t batteryLevel = it->second;
    HILOGI("batteryLevel: %{public}d, mac: %{public}s", batteryLevel, GetAnonymStr(mac_).c_str());
    if (!IsValidBatteryLevel(batteryLevel)) {
        HILOGE("abnormal battery level: %{public}d, mac: %{public}s", batteryLevel, GetAnonymStr(mac_).c_str());
        return;
    }
    CacheBatteryLevel(batteryLevel);
    NotifyBatteryLevelChange(batteryLevel);
}
 
void McBatteryManager::NotifyBatteryLevelChange(int32_t batteryLevel)
{
    bool isCharging = false;
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        isCharging = isCharging_;
    }
    HILOGI("mechId: %{public}d, batteryLevel: %{public}d, isCharging: %{public}d",
        mechId_, batteryLevel, isCharging);
    BatteryLevelChangeCallback cb;
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        cb = callback_;
    }
    if (cb != nullptr) {
        cb(mechId_, batteryLevel, isCharging);
    } else {
        HILOGW("battery level callback is nullptr, mechId: %{public}d", mechId_);
    }
}
 
} // namespace MechBodyController
} // namespace OHOS