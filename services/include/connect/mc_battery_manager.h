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
 
#ifndef MC_BATTERY_MANAGER_H
#define MC_BATTERY_MANAGER_H
 
#include <functional>
#include <mutex>
#include <string>
 
#include "bluetooth_bas_host.h"
#include "mechbody_controller_log.h"
#include "mechbody_controller_types.h"
 
namespace OHOS {
namespace MechBodyController {
 
using BatteryLevelChangeCallback = std::function<void(int32_t mechId, int32_t batteryLevel, bool isCharging)>;
 
enum BatteryLevelValue : int32_t {
    BATTERY_LEVEL_NOT_QUERIED = -2,
    BATTERY_LEVEL_NOT_SUPPORTED = -1,
    BATTERY_LEVEL_MIN = 0,
    BATTERY_LEVEL_MAX = 100,
};
 
class McBatteryManager : public Bluetooth::BluetoothRemoteDeviceBatteryObserver {
public:
    McBatteryManager();
    ~McBatteryManager();
 
    int32_t Init(const std::string &mac, int32_t mechId, const BatteryLevelChangeCallback &callback);
    void UnInit();
    bool IsObserverRegistered();
 
    void SetIsCharging(bool isCharging);
    int32_t GetCachedBatteryLevel();
    bool GetIsCharging();
    void RequestBatteryLevel();
 
private:
    void OnGetBatteryLevelEvent(const Bluetooth::BluetoothRemoteDevice &device, int32_t batteryLevel) override;
    void OnBatteryLevelChanged(const Bluetooth::BluetoothRemoteDevice &device, int32_t batteryLevel) override;
 
    void NotifyBatteryLevelChange(int32_t batteryLevel);
    void CacheBatteryLevel(int32_t batteryLevel);
    bool IsValidBatteryLevel(int32_t batteryLevel);
 
    std::string mac_;
    int32_t mechId_ = -1;
 
    std::mutex stateMutex_;
    int32_t cachedBatteryLevel_ = BATTERY_LEVEL_NOT_QUERIED;
    bool isCharging_ = false;
 
    std::mutex observerMutex_;
    bool isObserverRegistered_ = false;
 
    std::mutex callbackMutex_;
    BatteryLevelChangeCallback callback_;
};
 
} // namespace MechBodyController
} // namespace OHOS
#endif // MC_BATTERY_MANAGER_H