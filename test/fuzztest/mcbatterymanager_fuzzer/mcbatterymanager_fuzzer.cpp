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

#include "mcbatterymanager_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>

#include "mc_battery_manager.h"

namespace OHOS {
using namespace OHOS::MechBodyController;
namespace {
constexpr uint8_t MIN_CALL_COUNT = 1;
constexpr uint8_t MAX_CALL_COUNT = 5;
} // namespace


void InitFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    bool useCallback = fdp.ConsumeBool();
    std::string mac = fdp.ConsumeRandomLengthString();
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    BatteryLevelChangeCallback cb = useCallback
        ? [](int32_t, int32_t, bool) {} : nullptr;

    McBatteryManager manager;
    manager.Init(mac, mechId, cb);
    manager.UnInit();
}

void InitTwiceFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string mac = fdp.ConsumeRandomLengthString();
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    BatteryLevelChangeCallback cb = [](int32_t, int32_t, bool) {};

    McBatteryManager manager;
    manager.Init(mac, mechId, cb);
    manager.Init(mac, mechId, cb);
    manager.UnInit();
}

void UnInitWithoutInitFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    uint8_t callCount = fdp.ConsumeIntegralInRange<uint8_t>(MIN_CALL_COUNT, MAX_CALL_COUNT);
    McBatteryManager manager;
    for (uint8_t i = 0; i < callCount; i++) {
        manager.UnInit();
    }
}

void SetIsChargingFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    bool isCharging = fdp.ConsumeBool();
    uint32_t checkCount = fdp.ConsumeIntegralInRange<uint32_t>(MIN_CALL_COUNT, MAX_CALL_COUNT);

    McBatteryManager manager;
    manager.SetIsCharging(isCharging);
    for (uint32_t i = 0; i < checkCount; i++) {
        manager.GetIsCharging();
    }
}

void GetCachedBatteryLevelFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    uint32_t checkCount = fdp.ConsumeIntegralInRange<uint32_t>(MIN_CALL_COUNT, MAX_CALL_COUNT);

    McBatteryManager manager;
    for (uint32_t i = 0; i < checkCount; i++) {
        manager.GetCachedBatteryLevel();
    }
}

void IsObserverRegisteredFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    bool useCallback = fdp.ConsumeBool();
    std::string mac = fdp.ConsumeRandomLengthString();
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    BatteryLevelChangeCallback cb = useCallback
        ? [](int32_t, int32_t, bool) {} : nullptr;

    McBatteryManager manager;
    manager.Init(mac, mechId, cb);
    bool isRegistered = manager.IsObserverRegistered();
    (void)isRegistered;
    manager.UnInit();
}

void NotifyBatteryLevelChangeViaStateTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    bool isCharging = fdp.ConsumeBool();
    int32_t batteryLevel = fdp.ConsumeIntegral<int32_t>();

    McBatteryManager manager;
    manager.SetIsCharging(isCharging);
    manager.GetCachedBatteryLevel();
    manager.RequestBatteryLevel();
    (void)batteryLevel;
    manager.UnInit();
}

void CacheBatteryLevelViaPublicTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    bool isCharging = fdp.ConsumeBool();
    uint32_t checkCount = fdp.ConsumeIntegralInRange<uint32_t>(MIN_CALL_COUNT, MAX_CALL_COUNT);

    McBatteryManager manager;
    manager.SetIsCharging(isCharging);
    for (uint32_t i = 0; i < checkCount; i++) {
        manager.GetIsCharging();
        manager.GetCachedBatteryLevel();
    }
}

void RequestBatteryLevelFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    bool useCallback = fdp.ConsumeBool();
    std::string mac = fdp.ConsumeRandomLengthString();
    int32_t mechId = fdp.ConsumeIntegral<int32_t>();
    BatteryLevelChangeCallback cb = useCallback
        ? [](int32_t, int32_t, bool) {} : nullptr;

    McBatteryManager manager;
    manager.Init(mac, mechId, cb);
    manager.RequestBatteryLevel();
    manager.UnInit();
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    uint8_t action = fdp.ConsumeIntegral<uint8_t>() % FUZZ_FUNC_COUNT;
    auto remaining = fdp.ConsumeRemainingBytes<uint8_t>();
    const uint8_t *actionData = remaining.data();
    size_t actionSize = remaining.size();

    if (action < FUZZ_FUNC_COUNT) {
        FUZZ_FUNCS[action](actionData, actionSize);
    }
    return 0;
}
using FuzzFunc = void (*)(const uint8_t *, size_t);
const FuzzFunc FUZZ_FUNCS[] = {
    OHOS::InitFuzzTest,
    OHOS::InitTwiceFuzzTest,
    OHOS::UnInitWithoutInitFuzzTest,
    OHOS::SetIsChargingFuzzTest,
    OHOS::GetCachedBatteryLevelFuzzTest,
    OHOS::IsObserverRegisteredFuzzTest,
    OHOS::NotifyBatteryLevelChangeViaStateTest,
    OHOS::CacheBatteryLevelViaPublicTest,
    OHOS::RequestBatteryLevelFuzzTest,
};
constexpr size_t FUZZ_FUNC_COUNT = sizeof(FUZZ_FUNCS) / sizeof(FUZZ_FUNCS[0]);

} // namespace OHOS
