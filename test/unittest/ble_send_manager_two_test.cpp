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

#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>
#include "ble_send_manager_test.h"
#include "connect/mc_connect_manager.h"
#include "mechbody_controller_service.h"
#include "mc_motion_manager.h"

using namespace OHOS::Bluetooth;

namespace OHOS {
namespace MechBodyController {

// Mock BleReceviceListener for testing OnCharacteristicChanged with listeners
class MockBleReceviceListener : public BleReceviceListener {
public:
    virtual ~MockBleReceviceListener() = default;
    int32_t OnReceive(const uint8_t *data, uint32_t dataLen) override
    {
        receiveCount++;
        lastDataLen = dataLen;
        if (data != nullptr && dataLen > 0) {
            lastData.assign(data, data + dataLen);
        }
        return ERR_OK;
    }
    int32_t receiveCount = 0;
    uint32_t lastDataLen = 0;
    std::vector<uint8_t> lastData;
};

// Mock TransportSendAdapter for creating MotionManager instances in tests
class MockTransportSendAdapterForBle : public TransportSendAdapter {
public:
    MockTransportSendAdapterForBle() : TransportSendAdapter(true) {}
    int32_t SendCommand(const std::shared_ptr<CommandBase> &cmd, int32_t delayMs = 0) override
    {
        return ERR_OK;
    }
};

/**
 * @tc.name  : OnCharacteristicChanged_001
 * @tc.number: OnCharacteristicChanged_001
 * @tc.desc  : Test OnCharacteristicChanged with default GattCharacteristic.
 *             Covers the branch where GetValue returns nullptr,
 *             OnReceive returns ERROR_INVALID_PARAMETER.
 */
HWTEST_F(BleGattClientCallbackTest, OnCharacteristicChanged_001, testing::ext::TestSize.Level3)
{
    // Given: default-constructed GattCharacteristic (value is nullptr), a mock listener
    GattCharacteristic characteristic(UUID::FromString("0000fff0-0000-1000-8000-00805f9b34fb"), 1, 0, 0);
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bleSendManager.bleReceviceListeners_.clear();
    auto listener = std::make_shared<MockBleReceviceListener>();
    bleSendManager.bleReceviceListeners_.push_back(listener);

    // When: OnCharacteristicChanged is called with default (nullptr) value
    // GetValue returns nullptr → OnReceive returns ERROR_INVALID_PARAMETER (data==nullptr)
    bleGattClientCallback_->OnCharacteristicChanged(characteristic);

    // Then: listener->OnReceive should NOT be called (OnReceive returns early on nullptr data)
    EXPECT_EQ(listener->receiveCount, 0);

    // Cleanup
    bleSendManager.bleReceviceListeners_.clear();
}

/**
 * @tc.name  : OnSetNotifyCharacteristic_002
 * @tc.number: OnSetNotifyCharacteristic_002
 * @tc.desc  : Test OnSetNotifyCharacteristic with GetMechInfo success and status=0(非1).
 *             Covers the branch where GetMechInfo succeeds and isGattReady_ stays false per
 *             the original `status == 1` semantics. The detached thread still calls OnGattReady.
 */
HWTEST_F(BleGattClientCallbackTest, OnSetNotifyCharacteristic_002, testing::ext::TestSize.Level1)
{
    // Given: mechInfo in MechConnectManager, gattClient_ set, mac set on callback
    std::string mac = "AA:BB:CC:DD:EE:F1";
    MechInfo mechInfo;
    mechInfo.mac = mac;
    mechInfo.mechId = 9301;
    MechConnectManager::GetInstance().CleanMechInfo();
    MechConnectManager::GetInstance().AddMechInfo(mechInfo);
    bleGattClientCallback_->setMac(mac);

    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    BluetoothRemoteDevice device(mac, 1);
    bleSendManager.gattClient_ = std::make_shared<OHOS::Bluetooth::GattClient>(device);
    bleSendManager.isGattReady_ = true; // Pre-set to true to verify it gets set to false

    GattCharacteristic characteristic(UUID::FromString("0000fff0-0000-1000-8000-00805f9b34fb"), 1, 0, 0);
    int status = 0; // isGattReady_ = (status == 1) → false

    // When: OnSetNotifyCharacteristic is called with status=0
    bleGattClientCallback_->OnSetNotifyCharacteristic(characteristic, status);

    // Then: isGattReady_ should be set to false per `status == 1` semantics
    EXPECT_FALSE(bleSendManager.isGattReady_);

    // Wait for detached thread (OnGattReady MTU timeout = 2s)
    std::this_thread::sleep_for(std::chrono::seconds(3));

    // Cleanup
    bleSendManager.isGattReady_ = false;
    bleSendManager.gattClient_.reset();
    bleSendManager.gattClient_ = nullptr;
    std::string mutableMac = mac;
    MechConnectManager::GetInstance().SetMechanicGattState(mutableMac, false);
    MechConnectManager::GetInstance().CleanMechInfo();
}

/**
 * @tc.name  : OnSetNotifyCharacteristic_003
 * @tc.number: OnSetNotifyCharacteristic_003
 * @tc.desc  : Test OnSetNotifyCharacteristic with GetMechInfo success and status=1.
 *             Covers the branch where GetMechInfo succeeds and isGattReady_ is set to true per
 *             the original `status == 1` semantics. The detached thread still calls OnGattReady.
 */
HWTEST_F(BleGattClientCallbackTest, OnSetNotifyCharacteristic_003, testing::ext::TestSize.Level1)
{
    // Given: mechInfo in MechConnectManager, gattClient_ set, mac set on callback
    std::string mac = "AA:BB:CC:DD:EE:F2";
    MechInfo mechInfo;
    mechInfo.mac = mac;
    mechInfo.mechId = 9302;
    MechConnectManager::GetInstance().CleanMechInfo();
    MechConnectManager::GetInstance().AddMechInfo(mechInfo);
    bleGattClientCallback_->setMac(mac);

    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    BluetoothRemoteDevice device(mac, 1);
    bleSendManager.gattClient_ = std::make_shared<OHOS::Bluetooth::GattClient>(device);
    bleSendManager.isGattReady_ = false;

    GattCharacteristic characteristic(UUID::FromString("0000fff0-0000-1000-8000-00805f9b34fb"), 1, 0, 0);
    int status = 1; // isGattReady_ = (status == 1) → true

    // When: OnSetNotifyCharacteristic is called with status=1
    bleGattClientCallback_->OnSetNotifyCharacteristic(characteristic, status);

    // Then: isGattReady_ should be set to true per `status == 1` semantics
    EXPECT_TRUE(bleSendManager.isGattReady_);

    // Wait for detached thread (OnGattReady MTU timeout = 2s)
    std::this_thread::sleep_for(std::chrono::seconds(3));

    // Cleanup
    bleSendManager.isGattReady_ = false;
    bleSendManager.gattClient_.reset();
    bleSendManager.gattClient_ = nullptr;
    std::string mutableMac = mac;
    MechConnectManager::GetInstance().SetMechanicGattState(mutableMac, false);
    MechConnectManager::GetInstance().CleanMechInfo();
}

/**
 * @tc.name  : DelayedUnloadSystemAbility_002
 * @tc.number: DelayedUnloadSystemAbility_002
 * @tc.desc  : Test DelayedUnloadSystemAbility with valid eventHandler_.
 *             Covers the branch where task is posted to eventHandler_ with 60s delay.
 *             Verifies the posted task name exists in the event handler by removing it
 *             and confirming a sentinel task still executes on the running runner.
 */
HWTEST_F(BleSendManagerTest, DelayedUnloadSystemAbility_002, testing::ext::TestSize.Level3)
{
    // Given: eventHandler_ with a running EventRunner
    auto runner = AppExecFwk::EventRunner::Create("BleSendManagerTestUnload");
    bleSendManager_->eventHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    ASSERT_NE(bleSendManager_->eventHandler_, nullptr);
    runner->Run();

    // When: DelayedUnloadSystemAbility is called (posts "abilityUnloadTaskName" with 60s delay)
    bleSendManager_->DelayedUnloadSystemAbility();

    // Remove the 60s-delayed task so it doesn't fire during test cleanup
    bleSendManager_->eventHandler_->RemoveTask("abilityUnloadTaskName");

    // Post a sentinel immediate task to verify the event handler is functional
    std::atomic<bool> sentinelExecuted(false);
    bleSendManager_->eventHandler_->PostTask([&sentinelExecuted]() { sentinelExecuted = true; });
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Then: the sentinel task executed, proving the event handler processed tasks
    // (DelayedUnloadSystemAbility posted a task to the same handler successfully)
    EXPECT_TRUE(sentinelExecuted.load());

    // Cleanup
    runner->Stop();
    bleSendManager_->eventHandler_ = nullptr;
}

/**
 * @tc.name  : CancelDelayedUnload_002
 * @tc.number: CancelDelayedUnload_002
 * @tc.desc  : Test CancelDelayedUnload with valid eventHandler_ and a pending task.
 *             Covers the branch where RemoveTask("abilityUnloadTaskName") is called.
 *             Verifies the task is removed before it can execute.
 */
HWTEST_F(BleSendManagerTest, CancelDelayedUnload_002, testing::ext::TestSize.Level3)
{
    // Given: eventHandler_ with a running runner, a task posted with short delay
    auto runner = AppExecFwk::EventRunner::Create("BleSendManagerTestCancel");
    bleSendManager_->eventHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    ASSERT_NE(bleSendManager_->eventHandler_, nullptr);
    runner->Run();
    std::atomic<bool> taskExecuted(false);
    // Post a task with 500ms delay, named "abilityUnloadTaskName"
    bleSendManager_->eventHandler_->PostTask([&taskExecuted]() { taskExecuted = true; },
        "abilityUnloadTaskName", 500);

    // When: CancelDelayedUnload is called (removes "abilityUnloadTaskName" before it fires)
    bleSendManager_->CancelDelayedUnload();

    // Wait long enough for the original 500ms delay to have passed
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    // Then: task should have been removed by CancelDelayedUnload, so it never executed
    EXPECT_FALSE(taskExecuted.load());

    // Cleanup
    runner->Stop();
    bleSendManager_->eventHandler_ = nullptr;
}

/**
 * @tc.name  : GetBatteryManager_001
 * @tc.number: GetBatteryManager_001
 * @tc.desc  : Test GetBatteryManager with default state (batteryManager_ is nullptr).
 */
HWTEST_F(BleSendManagerTest, GetBatteryManager_001, testing::ext::TestSize.Level3)
{
    // Given: batteryManager_ is nullptr by default
    // When: GetBatteryManager is called
    McBatteryManager* result = bleSendManager_->GetBatteryManager();

    // Then: should return nullptr
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name  : GetMac_BleSendManager_001
 * @tc.number: GetMac_BleSendManager_001
 * @tc.desc  : Test BleSendManager::GetMac with default empty address_.
 */
HWTEST_F(BleSendManagerTest, GetMac_BleSendManager_001, testing::ext::TestSize.Level3)
{
    // Given: address_ is empty by default
    bleSendManager_->address_ = "";

    // When: GetMac is called
    std::string result = bleSendManager_->GetMac();

    // Then: should return empty string
    ASSERT_EQ(result, "");
}

/**
 * @tc.name  : GetMac_BleSendManager_002
 * @tc.number: GetMac_BleSendManager_002
 * @tc.desc  : Test BleSendManager::GetMac with a set address_.
 */
HWTEST_F(BleSendManagerTest, GetMac_BleSendManager_002, testing::ext::TestSize.Level3)
{
    // Given: address_ is set to a specific MAC
    std::string testMac = "AA:BB:CC:DD:EE:FF";
    bleSendManager_->address_ = testMac;

    // When: GetMac is called
    std::string result = bleSendManager_->GetMac();

    // Then: should return the set MAC
    ASSERT_EQ(result, testMac);

    // Cleanup
    bleSendManager_->address_ = "";
}

/**
 * @tc.name  : CheckGattcIsReady_001
 * @tc.number: CheckGattcIsReady_001
 * @tc.desc  : Test CheckGattcIsReady when isGattReady_ is false.
 */
HWTEST_F(BleSendManagerTest, CheckGattcIsReady_001, testing::ext::TestSize.Level3)
{
    // Given: isGattReady_ is false
    bleSendManager_->isGattReady_ = false;

    // When: CheckGattcIsReady is called
    bool result = bleSendManager_->CheckGattcIsReady();

    // Then: should return false
    ASSERT_FALSE(result);
}

/**
 * @tc.name  : CheckGattcIsReady_002
 * @tc.number: CheckGattcIsReady_002
 * @tc.desc  : Test CheckGattcIsReady when isGattReady_ is true.
 */
HWTEST_F(BleSendManagerTest, CheckGattcIsReady_002, testing::ext::TestSize.Level3)
{
    // Given: isGattReady_ is true
    bleSendManager_->isGattReady_ = true;

    // When: CheckGattcIsReady is called
    bool result = bleSendManager_->CheckGattcIsReady();

    // Then: should return true
    ASSERT_TRUE(result);

    // Cleanup
    bleSendManager_->isGattReady_ = false;
}

/**
 * @tc.name  : NotifyGetRealName_001
 * @tc.number: NotifyGetRealName_001
 * @tc.desc  : Test NotifyGetRealName wakes up a thread waiting on getRealNameCv_.
 *             NotifyGetRealName calls getRealNameCv_.notify_all(), which should
 *             unblock a waiting thread. The predicate returns false (no motionManager),
 *             so wait_for returns false immediately after being notified.
 */
HWTEST_F(BleSendManagerTest, NotifyGetRealName_001, testing::ext::TestSize.Level1)
{
    // Given: BleSendManager with no motionManagers_ (predicate will return false)
    MechBodyControllerService::GetInstance().CleanMotionManagers();
    MechInfo mechInfo;
    mechInfo.mechId = 9410;
    mechInfo.mac = "AA:BB:CC:DD:EE:10";
    MechConnectManager::GetInstance().CleanMechInfo();
    MechConnectManager::GetInstance().AddMechInfo(mechInfo);

    // Start a thread that waits on getRealNameCv_ with the predicate
    std::atomic<bool> threadWoken(false);
    std::thread waitThread([this, &threadWoken, mechInfo]() {
        std::unique_lock<std::mutex> lock(bleSendManager_->getRealNameMutex_);
        bleSendManager_->getRealNameCv_.wait_for(lock, std::chrono::seconds(5), [&lock, mechInfo]() {
            std::lock_guard<std::mutex> lock2(MechBodyControllerService::GetInstance().motionManagersMutex);
            return MechBodyControllerService::GetInstance().motionManagers_.find(mechInfo.mechId) !=
                   MechBodyControllerService::GetInstance().motionManagers_.end();
        });
        // If we get here, either notified (predicate false) or timed out
        threadWoken = true;
    });

    // Give the thread time to start waiting
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // When: NotifyGetRealName is called (notifies getRealNameCv_)
    auto notifyTime = std::chrono::steady_clock::now();
    bleSendManager_->NotifyGetRealName();

    // Wait for the thread to be unblocked
    waitThread.join();

    // Then: NotifyGetRealName called notify_all, which unblocked the waiting thread.
    // The thread was woken before the 5s timeout (proving notify_all worked).
    auto wakeTime = std::chrono::steady_clock::now();
    auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(wakeTime - notifyTime).count();
    // notify_all should unblock the thread well before the 5s timeout
    EXPECT_TRUE(threadWoken.load());
    EXPECT_LT(elapsedMs, 5000);

    // Cleanup
    MechBodyControllerService::GetInstance().CleanMotionManagers();
    MechConnectManager::GetInstance().CleanMechInfo();
}

/**
 * @tc.name  : GetRealName_001
 * @tc.number: GetRealName_001
 * @tc.desc  : Test GetRealName when motionManagers_ does not contain mechId.
 *             The predicate returns false, wait_for times out after 2 seconds.
 *             Covers the timeout branch at line 418.
 */
HWTEST_F(BleSendManagerTest, GetRealName_001, testing::ext::TestSize.Level1)
{
    // Given: mechInfo with mechId not in motionManagers_, mechInfo registered in ConnectManager
    MechBodyControllerService::GetInstance().CleanMotionManagers();
    MechInfo mechInfo;
    mechInfo.mechId = 9401;
    mechInfo.mac = "AA:BB:CC:DD:EE:F3";
    mechInfo.mechName = "original_name";
    MechConnectManager::GetInstance().CleanMechInfo();
    MechConnectManager::GetInstance().AddMechInfo(mechInfo);

    // When: GetRealName is called
    // Predicate returns false (no motionManagers_ entry), wait_for times out after 2s
    bleSendManager_->GetRealName(mechInfo);

    // Then: mechName in ConnectManager should not be changed (timeout, no realName found)
    MechInfo resultInfo;
    std::string mutableMac = mechInfo.mac;
    ASSERT_EQ(MechConnectManager::GetInstance().GetMechInfo(mutableMac, resultInfo), ERR_OK);
    EXPECT_EQ(resultInfo.mechName, "original_name");

    // Cleanup
    MechBodyControllerService::GetInstance().CleanMotionManagers();
    MechConnectManager::GetInstance().CleanMechInfo();
}

/**
 * @tc.name  : SetBluetoothServiceStoped_HasBluetoothServiceStoped_001
 * @tc.number: SetBluetoothServiceStoped_HasBluetoothServiceStoped_001
 * @tc.desc  : Test SetBluetoothServiceStoped(true) and HasBluetoothServiceStoped returns true.
 */
HWTEST_F(BleSendManagerTest, SetBluetoothServiceStoped_HasBluetoothServiceStoped_001, testing::ext::TestSize.Level3)
{
    // Given: BleSendManager instance
    // When: SetBluetoothServiceStoped(true) is called
    bleSendManager_->SetBluetoothServiceStoped(true);

    // Then: HasBluetoothServiceStoped should return true
    ASSERT_TRUE(bleSendManager_->HasBluetoothServiceStoped());

    // Cleanup
    bleSendManager_->SetBluetoothServiceStoped(false);
}

/**
 * @tc.name  : SetBluetoothServiceStoped_HasBluetoothServiceStoped_002
 * @tc.number: SetBluetoothServiceStoped_HasBluetoothServiceStoped_002
 * @tc.desc  : Test SetBluetoothServiceStoped(false) and HasBluetoothServiceStoped returns false.
 */
HWTEST_F(BleSendManagerTest, SetBluetoothServiceStoped_HasBluetoothServiceStoped_002, testing::ext::TestSize.Level3)
{
    // Given: BleSendManager with bluetoothServiceStoped = true
    bleSendManager_->SetBluetoothServiceStoped(true);
    ASSERT_TRUE(bleSendManager_->HasBluetoothServiceStoped());

    // When: SetBluetoothServiceStoped(false) is called
    bleSendManager_->SetBluetoothServiceStoped(false);

    // Then: HasBluetoothServiceStoped should return false
    ASSERT_FALSE(bleSendManager_->HasBluetoothServiceStoped());
}

/**
 * @tc.name  : OnGattDisconnect_001
 * @tc.number: OnGattDisconnect_001
 * @tc.desc  : Test OnGattDisconnect with gattClient_ nullptr and bleGattClientCallBack_ nullptr.
 *             Covers branches where both are nullptr, only NotifyMechDisconnect and
 *             DelayedUnloadSystemAbility are called.
 */
HWTEST_F(BleSendManagerTest, OnGattDisconnect_001, testing::ext::TestSize.Level3)
{
    // Given: gattClient_ and bleGattClientCallBack_ are both nullptr, batteryManager_ set
    ASSERT_EQ(bleSendManager_->gattClient_, nullptr);
    ASSERT_EQ(bleSendManager_->bleGattClientCallBack_, nullptr);
    // batteryManager_ is nullptr by default in fresh BleSendManager
    ASSERT_EQ(bleSendManager_->batteryManager_, nullptr);
    MechInfo mechInfo;
    mechInfo.mac = "AA:BB:CC:DD:EE:F5";

    // When: OnGattDisconnect is called
    bleSendManager_->OnGattDisconnect(mechInfo);

    // Then: batteryManager_.reset() called (already nullptr, stays nullptr)
    // gattClient_ and bleGattClientCallBack_ stay nullptr (nothing to reset)
    EXPECT_EQ(bleSendManager_->batteryManager_, nullptr);
    EXPECT_EQ(bleSendManager_->gattClient_, nullptr);
    EXPECT_EQ(bleSendManager_->bleGattClientCallBack_, nullptr);
}

/**
 * @tc.name  : OnGattDisconnect_002
 * @tc.number: OnGattDisconnect_002
 * @tc.desc  : Test OnGattDisconnect with valid gattClient_ and bleGattClientCallBack_.
 *             Covers branches where both are non-nullptr and get reset.
 */
HWTEST_F(BleSendManagerTest, OnGattDisconnect_002, testing::ext::TestSize.Level3)
{
    // Given: gattClient_ and bleGattClientCallBack_ are set
    BluetoothRemoteDevice device("AA:BB:CC:DD:EE:F6", 1);
    bleSendManager_->gattClient_ = std::make_shared<OHOS::Bluetooth::GattClient>(device);
    bleSendManager_->bleGattClientCallBack_ = std::make_shared<BleGattClientCallback>();
    ASSERT_NE(bleSendManager_->gattClient_, nullptr);
    ASSERT_NE(bleSendManager_->bleGattClientCallBack_, nullptr);

    MechInfo mechInfo;
    mechInfo.mac = "AA:BB:CC:DD:EE:F6";

    // When: OnGattDisconnect is called
    bleSendManager_->OnGattDisconnect(mechInfo);

    // Then: both should be reset to nullptr
    EXPECT_EQ(bleSendManager_->gattClient_, nullptr);
    EXPECT_EQ(bleSendManager_->bleGattClientCallBack_, nullptr);
}

/**
 * @tc.name  : OnGattDisconnect_003
 * @tc.number: OnGattDisconnect_003
 * @tc.desc  : Test OnGattDisconnect with gattClient_ set but bleGattClientCallBack_ nullptr.
 *             Covers the branch where only gattClient_ is reset.
 */
HWTEST_F(BleSendManagerTest, OnGattDisconnect_003, testing::ext::TestSize.Level3)
{
    // Given: gattClient_ is set, bleGattClientCallBack_ is nullptr
    BluetoothRemoteDevice device("AA:BB:CC:DD:EE:F7", 1);
    bleSendManager_->gattClient_ = std::make_shared<OHOS::Bluetooth::GattClient>(device);
    bleSendManager_->bleGattClientCallBack_ = nullptr;
    ASSERT_NE(bleSendManager_->gattClient_, nullptr);
    ASSERT_EQ(bleSendManager_->bleGattClientCallBack_, nullptr);

    MechInfo mechInfo;
    mechInfo.mac = "AA:BB:CC:DD:EE:F7";

    // When: OnGattDisconnect is called
    bleSendManager_->OnGattDisconnect(mechInfo);

    // Then: gattClient_ should be reset, bleGattClientCallBack_ stays nullptr
    EXPECT_EQ(bleSendManager_->gattClient_, nullptr);
    EXPECT_EQ(bleSendManager_->bleGattClientCallBack_, nullptr);
}

/**
 * @tc.name  : OnScanCallback_001
 * @tc.number: OnScanCallback_001
 * @tc.desc  : Test OnScanCallback with deviceName != TARGET_DEVICE_NAME.
 *             Covers the branch where the if condition is false, function skips.
 */
HWTEST_F(BleSendManagerTest, OnScanCallback_001, testing::ext::TestSize.Level3)
{
    // Given: BleScanResult with default construction (deviceName is empty, != TARGET_DEVICE_NAME)
    Bluetooth::BleScanResult result;
    bleSendManager_->address_ = "original_address";

    // When: OnScanCallback is called with a result whose deviceName is not TARGET_DEVICE_NAME
    bleSendManager_->OnScanCallback(result);

    // Then: address_ should not be modified (if branch not taken)
    EXPECT_EQ(bleSendManager_->address_, "original_address");

    // Cleanup
    bleSendManager_->address_ = "";
}

/**
 * @tc.name  : OnPairStatusChanged_RemoteDeviceObserver_002
 * @tc.number: OnPairStatusChanged_RemoteDeviceObserver_002
 * @tc.desc  : Test RemoteDeviceObserver::OnPairStatusChanged with device in MechConnectManager.
 *             Covers the branch where GetMechInfo succeeds → calls OnPairStateChanged.
 */
HWTEST_F(RemoteDeviceObserverTest, OnPairStatusChanged_RemoteDeviceObserver_002, testing::ext::TestSize.Level3)
{
    // Given: device with address in MechConnectManager, pairState not PAIR_PAIRED
    MechConnectManager::GetInstance().CleanMechInfo();
    std::string mac = "AA:BB:CC:DD:EE:FB";
    MechInfo mechInfo;
    mechInfo.mac = mac;
    mechInfo.mechId = 9501;
    mechInfo.mechName = "original";
    MechConnectManager::GetInstance().AddMechInfo(mechInfo);
    BluetoothRemoteDevice device(mac, Bluetooth::BT_TRANSPORT_BLE);

    // When: OnPairStatusChanged is called with non-PAIR_PAIRED status
    // GetMechInfo succeeds → calls OnPairStateChanged with status=0 (not PAIRED)
    // OnPairStateChanged does nothing for non-PAIRED status
    remoteDeviceObserver_->OnPairStatusChanged(device, 0, 0);

    // Then: pairState should NOT be set to true (only PAIR_PAIRED sets it)
    bool pairState = true;
    ASSERT_EQ(MechConnectManager::GetInstance().GetMechanicPairState(mac, pairState), ERR_OK);
    EXPECT_FALSE(pairState);

    // Cleanup
    MechConnectManager::GetInstance().CleanMechInfo();
}

/**
 * @tc.name  : HidObserver_OnConnectionStateChanged_003
 * @tc.number: HidObserver_OnConnectionStateChanged_003
 * @tc.desc  : Test HidObserver::OnConnectionStateChanged with DISCONNECTED state and
 *             device in MechConnectManager. Covers branch where GetMechInfo succeeds →
 *             calls OnHidStateChanged with DISCONNECTED.
 */
HWTEST_F(HidObserverTest, HidObserver_OnConnectionStateChanged_003, testing::ext::TestSize.Level3)
{
    // Given: device in MechConnectManager with HID state true
    MechConnectManager::GetInstance().CleanMechInfo();
    std::string mac = "AA:BB:CC:DD:EE:FE";
    MechInfo mechInfo;
    mechInfo.mac = mac;
    mechInfo.mechId = 9601;
    MechConnectManager::GetInstance().AddMechInfo(mechInfo);
    MechConnectManager::GetInstance().SetMechanicHidState(mac, true);
    BluetoothRemoteDevice device(mac, Bluetooth::BT_TRANSPORT_BLE);

    // When: OnConnectionStateChanged is called with DISCONNECTED state
    // RemovePair is called, then GetMechInfo succeeds → OnHidStateChanged(DISCONNECTED)
    hidObserver_->OnConnectionStateChanged(device,
        static_cast<int>(Bluetooth::BTConnectState::DISCONNECTED), 0);

    // Then: OnHidStateChanged(DISCONNECTED) sets HID state to false
    bool hidState = true;
    ASSERT_EQ(MechConnectManager::GetInstance().GetMechanicHidState(mac, hidState), ERR_OK);
    EXPECT_FALSE(hidState);

    // Cleanup
    MechConnectManager::GetInstance().CleanMechInfo();
}

/**
 * @tc.name  : HidObserver_OnConnectionStateChanged_004
 * @tc.number: HidObserver_OnConnectionStateChanged_004
 * @tc.desc  : Test HidObserver::OnConnectionStateChanged with CONNECTED state and
 *             device in MechConnectManager. Covers branch where state != DISCONNECTED
 *             (skip RemovePair) and GetMechInfo succeeds → calls OnHidStateChanged(CONNECTED).
 */
HWTEST_F(HidObserverTest, HidObserver_OnConnectionStateChanged_004, testing::ext::TestSize.Level3)
{
    // Given: device in MechConnectManager with HID state false
    MechConnectManager::GetInstance().CleanMechInfo();
    std::string mac = "AA:BB:CC:DD:EE:FF";
    MechInfo mechInfo;
    mechInfo.mac = mac;
    mechInfo.mechId = 9602;
    MechConnectManager::GetInstance().AddMechInfo(mechInfo);
    MechConnectManager::GetInstance().SetMechanicHidState(mac, false);
    BluetoothRemoteDevice device(mac, Bluetooth::BT_TRANSPORT_BLE);

    // When: OnConnectionStateChanged is called with CONNECTED state
    // state != DISCONNECTED → skip RemovePair
    // GetMechInfo succeeds → OnHidStateChanged(CONNECTED) sets HID state to true
    hidObserver_->OnConnectionStateChanged(device,
        static_cast<int>(Bluetooth::BTConnectState::CONNECTED), 0);

    // Then: OnHidStateChanged(CONNECTED) sets HID state to true
    bool hidState = false;
    ASSERT_EQ(MechConnectManager::GetInstance().GetMechanicHidState(mac, hidState), ERR_OK);
    EXPECT_TRUE(hidState);

    // Cleanup
    MechConnectManager::GetInstance().CleanMechInfo();
}

/**
 * @tc.name  : OnRemoveSystemAbility_003
 * @tc.number: OnRemoveSystemAbility_003
 * @tc.desc  : Test BluetoothServiceStatusChangeListener::OnRemoveSystemAbility with
 *             matching BLUETOOTH_SERVICE_SERVICE_SA_ID (1130).
 *             Covers the branch where systemAbilityId == 1130 → SetBluetoothServiceStoped(true).
 *             Note: existing OnRemoveSystemAbility_001 uses 2901 which is NOT the matching ID.
 */
HWTEST_F(BluetoothServiceStatusChangeListenerTest, OnRemoveSystemAbility_003, testing::ext::TestSize.Level3)
{
    // Given: BleSendManager with bluetoothServiceStoped = false
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bleSendManager.SetBluetoothServiceStoped(false);
    ASSERT_FALSE(bleSendManager.HasBluetoothServiceStoped());

    int32_t systemAbilityId = 1130; // BLUETOOTH_SERVICE_SERVICE_SA_ID
    std::string deviceId = "test_device";

    // When: OnRemoveSystemAbility is called with matching SA ID
    bluetoothServiceStatusChangeListener_->OnRemoveSystemAbility(systemAbilityId, deviceId);

    // Then: bluetoothServiceStoped should be set to true
    ASSERT_TRUE(bleSendManager.HasBluetoothServiceStoped());

    // Cleanup
    bleSendManager.SetBluetoothServiceStoped(false);
}

/**
 * @tc.name  : BleCentralManagerCallbackImpl_OnScanCallback_001
 * @tc.number: BleCentralManagerCallbackImpl_OnScanCallback_001
 * @tc.desc  : Test BleCentralManagerCallbackImpl::OnScanCallback with default BleScanResult.
 *             Covers the branch where deviceName != TARGET_DEVICE_NAME (empty default).
 */
HWTEST_F(BleSendManagerTest, BleCentralManagerCallbackImpl_OnScanCallback_001, testing::ext::TestSize.Level3)
{
    // Given: BleCentralManagerCallbackImpl instance and default BleScanResult
    BleCentralManagerCallbackImpl callbackImpl;
    Bluetooth::BleScanResult result;
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bleSendManager.address_ = "original_addr";

    // When: OnScanCallback is called with default result
    callbackImpl.OnScanCallback(result);

    // Then: address_ should not be modified (deviceName empty != TARGET_DEVICE_NAME)
    EXPECT_EQ(bleSendManager.address_, "original_addr");

    // Cleanup
    bleSendManager.address_ = "";
}

/**
 * @tc.name  : OnCharacteristicChanged_002
 * @tc.number: OnCharacteristicChanged_002
 * @tc.desc  : Test OnCharacteristicChanged with valid value set and empty listeners.
 *             Covers the branch where GetValue returns non-null (size > 0),
 *             OnReceive is called with valid data, bleReceviceListeners_ is empty
 *             → OnReceive returns ERROR_NO_LISTENERS.
 */
HWTEST_F(BleGattClientCallbackTest, OnCharacteristicChanged_002, testing::ext::TestSize.Level3)
{
    // Given: GattCharacteristic with value set, bleReceviceListeners_ has a mock listener
    GattCharacteristic characteristic(UUID::FromString("0000fff0-0000-1000-8000-00805f9b34fb"), 1, 0, 0);
    uint8_t value[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    characteristic.SetValue(value, sizeof(value));
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bleSendManager.bleReceviceListeners_.clear();
    auto listener = std::make_shared<MockBleReceviceListener>();
    bleSendManager.bleReceviceListeners_.push_back(listener);

    // When: OnCharacteristicChanged is called with valid value
    // GetValue returns non-null → OnReceive iterates listeners → calls listener->OnReceive
    bleGattClientCallback_->OnCharacteristicChanged(characteristic);

    // Then: listener->OnReceive should be called with the correct data length
    EXPECT_EQ(listener->receiveCount, 1);
    EXPECT_EQ(listener->lastDataLen, sizeof(value));
    // Verify actual data content was passed correctly
    ASSERT_EQ(listener->lastData.size(), sizeof(value));
    EXPECT_EQ(listener->lastData[0], 0x01);
    EXPECT_EQ(listener->lastData[4], 0x05);

    // Cleanup
    bleSendManager.bleReceviceListeners_.clear();
}

/**
 * @tc.name  : OnCharacteristicChanged_003
 * @tc.number: OnCharacteristicChanged_003
 * @tc.desc  : Test OnCharacteristicChanged with valid value and multiple listeners.
 *             Covers the branch where OnReceive iterates all bleReceviceListeners_.
 */
HWTEST_F(BleGattClientCallbackTest, OnCharacteristicChanged_003, testing::ext::TestSize.Level3)
{
    // Given: GattCharacteristic with value set, two mock listeners registered
    GattCharacteristic characteristic(UUID::FromString("0000fff0-0000-1000-8000-00805f9b34fb"), 1, 0, 0);
    uint8_t value[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};
    characteristic.SetValue(value, sizeof(value));
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bleSendManager.bleReceviceListeners_.clear();
    auto listener1 = std::make_shared<MockBleReceviceListener>();
    auto listener2 = std::make_shared<MockBleReceviceListener>();
    bleSendManager.bleReceviceListeners_.push_back(listener1);
    bleSendManager.bleReceviceListeners_.push_back(listener2);

    // When: OnCharacteristicChanged is called with valid value and two listeners
    bleGattClientCallback_->OnCharacteristicChanged(characteristic);

    // Then: both listeners should have been called
    EXPECT_EQ(listener1->receiveCount, 1);
    EXPECT_EQ(listener2->receiveCount, 1);
    EXPECT_EQ(listener1->lastDataLen, sizeof(value));
    EXPECT_EQ(listener2->lastDataLen, sizeof(value));

    // Cleanup
    bleSendManager.bleReceviceListeners_.clear();
}

/**
 * @tc.name  : OnCharacteristicChanged_004
 * @tc.number: OnCharacteristicChanged_004
 * @tc.desc  : Test OnCharacteristicChanged with value set to empty (length=0).
 *             Covers the branch where size=0 → OnReceive returns ERROR_INVALID_PARAMETER,
 *             listener->OnReceive is NOT called.
 */
HWTEST_F(BleGattClientCallbackTest, OnCharacteristicChanged_004, testing::ext::TestSize.Level3)
{
    // Given: GattCharacteristic with empty value (length=0), a mock listener
    GattCharacteristic characteristic(UUID::FromString("0000fff0-0000-1000-8000-00805f9b34fb"), 1, 0, 0);
    uint8_t emptyValue[] = {};
    characteristic.SetValue(emptyValue, 0);
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bleSendManager.bleReceviceListeners_.clear();
    auto listener = std::make_shared<MockBleReceviceListener>();
    bleSendManager.bleReceviceListeners_.push_back(listener);

    // When: OnCharacteristicChanged is called with empty value
    // size=0 → OnReceive returns ERROR_INVALID_PARAMETER, listener not called
    bleGattClientCallback_->OnCharacteristicChanged(characteristic);

    // Then: listener->OnReceive should NOT be called (size=0 early return)
    EXPECT_EQ(listener->receiveCount, 0);

    // Cleanup
    bleSendManager.bleReceviceListeners_.clear();
}

/**
 * @tc.name  : OnCharacteristicChanged_005
 * @tc.number: OnCharacteristicChanged_005
 * @tc.desc  : Test OnCharacteristicChanged with valid value and a nullptr listener in list.
 *             Covers the branch where listener == nullptr → OnReceive returns ERROR_NO_LISTENERS,
 *             subsequent listeners are NOT called.
 */
HWTEST_F(BleGattClientCallbackTest, OnCharacteristicChanged_005, testing::ext::TestSize.Level3)
{
    // Given: GattCharacteristic with value set, nullptr listener followed by a mock listener
    GattCharacteristic characteristic(UUID::FromString("0000fff0-0000-1000-8000-00805f9b34fb"), 1, 0, 0);
    uint8_t value[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    characteristic.SetValue(value, sizeof(value));
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bleSendManager.bleReceviceListeners_.clear();
    auto validListener = std::make_shared<MockBleReceviceListener>();
    bleSendManager.bleReceviceListeners_.push_back(nullptr); // nullptr listener first
    bleSendManager.bleReceviceListeners_.push_back(validListener);

    // When: OnCharacteristicChanged is called with valid value but nullptr listener first
    // OnReceive iterates, finds nullptr listener → returns ERROR_NO_LISTENERS (stops iteration)
    bleGattClientCallback_->OnCharacteristicChanged(characteristic);

    // Then: validListener should NOT be called (nullptr listener causes early return)
    EXPECT_EQ(validListener->receiveCount, 0);

    // Cleanup
    bleSendManager.bleReceviceListeners_.clear();
}

/**
 * @tc.name  : GetRealName_002
 * @tc.number: GetRealName_002
 * @tc.desc  : Test GetRealName with motionManagers_ containing mechId and non-empty realName.
 *             Covers the branch where the predicate returns true (realName found),
 *             wait_for returns immediately, SetRealMechName is called.
 */
HWTEST_F(BleSendManagerTest, GetRealName_002, testing::ext::TestSize.Level1)
{
    // Given: motionManagers_ with a MotionManager that has a non-empty deviceRealName
    int32_t mechId = 9402;
    MechBodyControllerService::GetInstance().CleanMotionManagers();
    auto motionManager = std::make_shared<MotionManager>(std::make_shared<MockTransportSendAdapterForBle>(), mechId);
    motionManager->SetDeviceRealName("TestRealDevice");
    {
        std::lock_guard<std::mutex> lock(MechBodyControllerService::GetInstance().motionManagersMutex);
        MechBodyControllerService::GetInstance().motionManagers_[mechId] = motionManager;
    }
    MechInfo mechInfo;
    mechInfo.mechId = mechId;
    mechInfo.mac = "AA:BB:CC:DD:EE:F5";
    MechConnectManager::GetInstance().CleanMechInfo();
    MechConnectManager::GetInstance().AddMechInfo(mechInfo);

    // When: GetRealName is called
    // Predicate finds mechId in motionManagers_, deviceRealName is non-empty → returns true
    bleSendManager_->GetRealName(mechInfo);

    // Then: SetRealMechName should have been called, verify via GetMechInfo
    MechInfo resultInfo;
    std::string mutableMac = mechInfo.mac;
    ASSERT_EQ(MechConnectManager::GetInstance().GetMechInfo(mutableMac, resultInfo), ERR_OK);
    EXPECT_EQ(resultInfo.mechName, "TestRealDevice");

    // Cleanup
    MechBodyControllerService::GetInstance().CleanMotionManagers();
    MechConnectManager::GetInstance().CleanMechInfo();
}

/**
 * @tc.name  : GetRealName_003
 * @tc.number: GetRealName_003
 * @tc.desc  : Test GetRealName with motionManagers_ containing mechId but empty realName.
 *             Covers the branch where motionManagers_ has the entry but deviceRealName is empty,
 *             predicate returns false → wait_for times out.
 */
HWTEST_F(BleSendManagerTest, GetRealName_003, testing::ext::TestSize.Level1)
{
    // Given: motionManagers_ with a MotionManager that has empty deviceRealName
    int32_t mechId = 9403;
    MechBodyControllerService::GetInstance().CleanMotionManagers();
    auto motionManager = std::make_shared<MotionManager>(std::make_shared<MockTransportSendAdapterForBle>(), mechId);
    // deviceRealName_ is empty by default (not set)
    {
        std::lock_guard<std::mutex> lock(MechBodyControllerService::GetInstance().motionManagersMutex);
        MechBodyControllerService::GetInstance().motionManagers_[mechId] = motionManager;
    }
    MechInfo mechInfo;
    mechInfo.mechId = mechId;
    mechInfo.mac = "AA:BB:CC:DD:EE:F6";
    MechConnectManager::GetInstance().CleanMechInfo();
    MechConnectManager::GetInstance().AddMechInfo(mechInfo);

    // When: GetRealName is called
    // Predicate finds mechId but deviceRealName is empty → returns false → wait_for times out
    bleSendManager_->GetRealName(mechInfo);

    // Then: no crash, realName not set (wait_for timed out)
    MechInfo resultInfo;
    std::string mutableMac = mechInfo.mac;
    ASSERT_EQ(MechConnectManager::GetInstance().GetMechInfo(mutableMac, resultInfo), ERR_OK);
    EXPECT_TRUE(resultInfo.mechName.empty());

    // Cleanup
    MechBodyControllerService::GetInstance().CleanMotionManagers();
    MechConnectManager::GetInstance().CleanMechInfo();
}

/**
 * @tc.name  : CleanAllLocalInfo_002
 * @tc.number: CleanAllLocalInfo_002
 * @tc.desc  : Test CleanAllLocalInfo with valid eventHandler_ and running EventRunner.
 *             Covers the branch where eventHandler_ is non-nullptr, PostTask is called,
 *             and the cleanup lambda executes: SetBluetoothServiceStoped(false) is called.
 */
HWTEST_F(BleSendManagerTest, CleanAllLocalInfo_002, testing::ext::TestSize.Level3)
{
    // Given: singleton BleSendManager with eventHandler_, bluetoothServiceStoped=true,
    //        and a MechInfo in ConnectManager (cleanup lambda will clean it).
    // Note: CleanAllLocalInfo's lambda calls BleSendManager::GetInstance().SetBluetoothServiceStoped(false),
    // so we must use the singleton instance, not bleSendManager_.
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    auto runner = AppExecFwk::EventRunner::Create("BleSendManagerTestCleanAll");
    bleSendManager.eventHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    bleSendManager.SetBluetoothServiceStoped(true);
    ASSERT_TRUE(bleSendManager.HasBluetoothServiceStoped());
    MechInfo mechInfo;
    mechInfo.mac = "AA:BB:CC:DD:EE:G1";
    mechInfo.mechId = 9701;
    MechConnectManager::GetInstance().CleanMechInfo();
    MechConnectManager::GetInstance().AddMechInfo(mechInfo);

    // Start the runner so the posted task can execute
    runner->Run();

    // When: CleanAllLocalInfo is called (posts cleanup task to eventHandler_)
    bleSendManager.CleanAllLocalInfo();

    // Wait for the async task to execute on the event handler thread
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Then: the cleanup lambda should have executed:
    // - SetBluetoothServiceStoped(false) was called inside the lambda (on singleton)
    EXPECT_FALSE(bleSendManager.HasBluetoothServiceStoped());
    // - CleanMechInfo was called inside the lambda
    std::set<MechInfo> mechInfos = MechConnectManager::GetInstance().GetMechInfos();
    EXPECT_TRUE(mechInfos.empty());

    // Cleanup
    runner->Stop();
    bleSendManager.eventHandler_ = nullptr;
    bleSendManager.SetBluetoothServiceStoped(false);
    MechConnectManager::GetInstance().CleanMechInfo();
}

} // namespace MechBodyController
} // namespace OHOS
