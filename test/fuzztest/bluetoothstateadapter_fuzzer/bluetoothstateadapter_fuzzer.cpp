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

#include "bluetoothstateadapter_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>

#include "bluetooth_state_adapter.h"
#include "mc_connect_manager.h"
#include "mechbody_controller_log.h"
#include "mechbody_controller_types.h"

namespace OHOS {
using namespace OHOS::MechBodyController;
namespace {
const std::string TAG = "BluetoothStateAdapterFuzzTest";
}

void UpdateBleStatusFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    bool isBTActive = fdp.ConsumeBool();
    bool isBLEActive = fdp.ConsumeBool();

    // UpdateBTState/UpdateBLEState trigger MechConnectManager::UpdateBleStatus
    // with combined boolean logic - this is the core downstream business logic
    BluetoothStateAdapter& adapter = BluetoothStateAdapter::GetInstance();
    adapter.UpdateBTState(isBTActive);
    adapter.UpdateBLEState(isBLEActive);

    // Verify the downstream state through MechConnectManager
    MechConnectManager& connectMgr = MechConnectManager::GetInstance();
    (void)connectMgr.GetLocalDeviceBleStatus();

    // Toggle to test different combined state transitions
    adapter.UpdateBTState(!isBTActive);
    (void)connectMgr.GetLocalDeviceBleStatus();

    adapter.UpdateBLEState(!isBLEActive);
    (void)connectMgr.GetLocalDeviceBleStatus();

    // Verify adapter's combined state
    (void)adapter.IsBluetoothActive();
}

void NotifyMechStateFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);

    // Add a MechInfo entry first so NotifyMechState can find it
    MechConnectManager& connectMgr = MechConnectManager::GetInstance();
    MechInfo testMech;
    testMech.mechId = fdp.ConsumeIntegral<int32_t>();
    testMech.mechType = static_cast<MechType>(fdp.ConsumeIntegralInRange<int32_t>(-1, 2));
    testMech.mac = fdp.ConsumeRandomLengthString(17);
    testMech.state = static_cast<AttachmentState>(fdp.ConsumeIntegralInRange<int32_t>(-1, 1));
    testMech.isFirstConnect = fdp.ConsumeBool();
    testMech.deviceIdentifier = fdp.ConsumeIntegral<uint32_t>();

    connectMgr.AddMechInfo(testMech);

    bool isAttached = fdp.ConsumeBool();
    bool forceDisconnect = fdp.ConsumeBool();
    connectMgr.NotifyMechState(testMech.mechId, isAttached, forceDisconnect);

    // Test GetMechBasicInfo after state update
    MechInfo retrievedInfo;
    (void)connectMgr.GetMechBasicInfo(testMech.mechId, retrievedInfo);

    // Test GetMechState
    (void)connectMgr.GetMechState(testMech.mechId);
}

void SetMechanicStatesFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);

    // Add a MechInfo entry to operate on
    MechConnectManager& connectMgr = MechConnectManager::GetInstance();
    MechInfo testMech;
    testMech.mechId = fdp.ConsumeIntegral<int32_t>();
    testMech.mechType = static_cast<MechType>(fdp.ConsumeIntegralInRange<int32_t>(-1, 2));
    testMech.mac = fdp.ConsumeRandomLengthString(17);
    testMech.state = static_cast<AttachmentState>(fdp.ConsumeIntegralInRange<int32_t>(-1, 1));

    connectMgr.AddMechInfo(testMech);

    // Test GATT/Pair/HID state setters with fuzz data
    std::string mac = testMech.mac;
    bool gattState = fdp.ConsumeBool();
    bool pairState = fdp.ConsumeBool();
    bool hidState = fdp.ConsumeBool();

    (void)connectMgr.SetMechanicGattState(mac, gattState);
    (void)connectMgr.SetMechanicPairState(mac, pairState);
    (void)connectMgr.SetMechanicHidState(mac, hidState);

    // Read back and verify
    bool outGattState = false;
    bool outPairState = false;
    bool outHidState = false;
    (void)connectMgr.GetMechanicGattState(mac, outGattState);
    (void)connectMgr.GetMechanicPairState(mac, outPairState);
    (void)connectMgr.GetMechanicHidState(mac, outHidState);
}

void IsBluetoothActiveFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    BluetoothStateAdapter& adapter = BluetoothStateAdapter::GetInstance();

    (void)adapter.IsBluetoothActive();
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::UpdateBleStatusFuzzTest(data, size);
    OHOS::NotifyMechStateFuzzTest(data, size);
    OHOS::SetMechanicStatesFuzzTest(data, size);
    OHOS::IsBluetoothActiveFuzzTest(data, size);
    return 0;
}
} // namespace OHOS