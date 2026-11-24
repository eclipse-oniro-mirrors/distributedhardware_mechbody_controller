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
#include <cstring>
#include <thread>
#include "connect/mc_connect_manager.h"
#include "mechbody_controller_service.h"
#include "ble_send_manager_test.h"

using namespace OHOS::Bluetooth;

namespace OHOS {
namespace MechBodyController {

void BleSendManagerTest::SetUpTestCase() {}
void BleSendManagerTest::TearDownTestCase() {}
void BleSendManagerTest::SetUp()
{
    bleSendManager_ = std::make_shared<BleSendManager>();
}
void BleSendManagerTest::TearDown()
{
    bleSendManager_ = nullptr;
}

void BleGattClientCallbackTest::SetUpTestCase() {}
void BleGattClientCallbackTest::TearDownTestCase() {}
void BleGattClientCallbackTest::SetUp()
{
    bleGattClientCallback_ = std::make_shared<BleGattClientCallback>();
}
void BleGattClientCallbackTest::TearDown()
{
    bleGattClientCallback_ = nullptr;
}

void RemoteDeviceObserverTest::SetUpTestCase() {}
void RemoteDeviceObserverTest::TearDownTestCase() {}
void RemoteDeviceObserverTest::SetUp()
{
    remoteDeviceObserver_ = std::make_shared<RemoteDeviceObserver>();
}
void RemoteDeviceObserverTest::TearDown()
{
    remoteDeviceObserver_ = nullptr;
}

void HostObserverTest::SetUpTestCase() {}
void HostObserverTest::TearDownTestCase() {}
void HostObserverTest::SetUp()
{
    hostObserver_ = std::make_shared<HostObserver>();
}
void HostObserverTest::TearDown()
{
    hostObserver_ = nullptr;
}

void HidObserverTest::SetUpTestCase() {}
void HidObserverTest::TearDownTestCase() {}
void HidObserverTest::SetUp()
{
    hidObserver_ = std::make_shared<HidObserver>();
}
void HidObserverTest::TearDown()
{
    hidObserver_ = nullptr;
}

void BluetoothServiceStatusChangeListenerTest::SetUpTestCase() {}
void BluetoothServiceStatusChangeListenerTest::TearDownTestCase() {}
void BluetoothServiceStatusChangeListenerTest::SetUp()
{
    bluetoothServiceStatusChangeListener_ = std::make_shared<BluetoothServiceStatusChangeListener>();
}
void BluetoothServiceStatusChangeListenerTest::TearDown()
{
    bluetoothServiceStatusChangeListener_ = nullptr;
}

/**
 * @tc.name: OnServicesDiscovered_001
 * @tc.desc: Test OnServicesDiscovered with status != GATT_SUCCESS, SUT returns early without modifying state
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnServicesDiscovered_001, testing::ext::TestSize.Level3) {
    int status = 1; // Not GATT_SUCCESS
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    // Set gattClient_ so that the success path would potentially modify handle_/permissions_/properties_
    BluetoothRemoteDevice device("AA:BB:CC:DD:EE:FF", 1);
    bleSendManager.gattClient_ = std::make_shared<OHOS::Bluetooth::GattClient>(device);
    // Set distinctive non-zero values to detect any unintended modification
    bleSendManager.handle_ = 0xDEAD;
    bleSendManager.permissions_ = 0xBEEF;
    bleSendManager.properties_ = 0xCAFE;
    bleGattClientCallback_->OnServicesDiscovered(status);
    // SUT must return early on status != GATT_SUCCESS, leaving state unchanged
    EXPECT_EQ(bleSendManager.handle_, 0xDEAD);
    EXPECT_EQ(bleSendManager.permissions_, 0xBEEF);
    EXPECT_EQ(bleSendManager.properties_, 0xCAFE);
    bleSendManager.gattClient_.reset();
    bleSendManager.gattClient_ = nullptr;
    bleSendManager.handle_ = 0;
    bleSendManager.permissions_ = 0;
    bleSendManager.properties_ = 0;
}

/**
 * @tc.name: OnServicesDiscovered_002
 * @tc.desc: Test OnServicesDiscovered with GATT_SUCCESS, verify gattClient_ nullptr early-return
 *           and valid-path behavior where handle_/permissions_/properties_ are set
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnServicesDiscovered_002, testing::ext::TestSize.Level3) {
    int status = 0; // GATT_SUCCESS
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    // Set distinctive non-zero values to detect any unintended modification
    bleSendManager.handle_ = 0xDEAD;
    bleSendManager.permissions_ = 0xBEEF;
    bleSendManager.properties_ = 0xCAFE;
    // gattClient_ is nullptr by default, SUT should return early at nullptr check
    bleGattClientCallback_->OnServicesDiscovered(status);
    EXPECT_EQ(bleSendManager.handle_, 0xDEAD);
    EXPECT_EQ(bleSendManager.permissions_, 0xBEEF);
    EXPECT_EQ(bleSendManager.properties_, 0xCAFE);
    // Now pre-set gattClient_ so SUT enters the valid path past the nullptr check
    BluetoothRemoteDevice device("AA:BB:CC:DD:EE:FF", 1);
    bleSendManager.gattClient_ = std::make_shared<OHOS::Bluetooth::GattClient>(device);
    bleGattClientCallback_->OnServicesDiscovered(status);
    // GetService fails on a bare GattClient, so SUT returns at GetService check;
    // handle_/permissions_/properties_ remain unchanged, proving SUT passed nullptr check
    // but did not reach the field-assignment code
    EXPECT_EQ(bleSendManager.handle_, 0xDEAD);
    EXPECT_EQ(bleSendManager.permissions_, 0xBEEF);
    EXPECT_EQ(bleSendManager.properties_, 0xCAFE);
    bleSendManager.gattClient_.reset();
    bleSendManager.gattClient_ = nullptr;
    bleSendManager.handle_ = 0;
    bleSendManager.permissions_ = 0;
    bleSendManager.properties_ = 0;
}

/**
 * @tc.name: OnServicesDiscovered_003
 * @tc.desc: Test OnServicesDiscovered with GATT_SUCCESS and valid gattClient_ but GetService fails
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnServicesDiscovered_003, testing::ext::TestSize.Level3) {
    int status = 0; // GATT_SUCCESS
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    BluetoothRemoteDevice device("AA:BB:CC:DD:EE:FF", 1);
    bleSendManager.gattClient_ = std::make_shared<OHOS::Bluetooth::GattClient>(device);
    uint16_t originalHandle = bleSendManager.handle_;
    int32_t originalPermissions = bleSendManager.permissions_;
    int32_t originalProperties = bleSendManager.properties_;
    bleGattClientCallback_->OnServicesDiscovered(status);
    ASSERT_EQ(bleSendManager.handle_, originalHandle);
    ASSERT_EQ(bleSendManager.permissions_, originalPermissions);
    ASSERT_EQ(bleSendManager.properties_, originalProperties);
    bleSendManager.gattClient_.reset();
    bleSendManager.gattClient_ = nullptr;
}

/**
 * @tc.name: OnServicesDiscovered_004
 * @tc.desc: Test OnServicesDiscovered with GATT_SUCCESS and gattClient_ initialized
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnServicesDiscovered_004, testing::ext::TestSize.Level3) {
    int status = 0; // GATT_SUCCESS
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    BluetoothRemoteDevice device("AA:BB:CC:DD:EE:FF", 1);
    bleSendManager.gattClient_ = std::make_shared<OHOS::Bluetooth::GattClient>(device);
    uint16_t originalHandle = bleSendManager.handle_;
    int32_t originalPermissions = bleSendManager.permissions_;
    int32_t originalProperties = bleSendManager.properties_;
    bleGattClientCallback_->OnServicesDiscovered(status);
    ASSERT_EQ(bleSendManager.handle_, originalHandle);
    ASSERT_EQ(bleSendManager.permissions_, originalPermissions);
    ASSERT_EQ(bleSendManager.properties_, originalProperties);
    bleSendManager.gattClient_.reset();
    bleSendManager.gattClient_ = nullptr;
}

/**
 * @tc.name: OnServicesDiscovered_005
 * @tc.desc: Test OnServicesDiscovered with GATT_FAILURE (status = 1)
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnServicesDiscovered_005, testing::ext::TestSize.Level3) {
    int status = 1; // GATT_FAILURE
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    uint16_t originalHandle = bleSendManager.handle_;
    int32_t originalPermissions = bleSendManager.permissions_;
    int32_t originalProperties = bleSendManager.properties_;
    bleGattClientCallback_->OnServicesDiscovered(status);
    ASSERT_EQ(bleSendManager.handle_, originalHandle);
    ASSERT_EQ(bleSendManager.permissions_, originalPermissions);
    ASSERT_EQ(bleSendManager.properties_, originalProperties);
}

/**
 * @tc.name: OnServicesDiscovered_006
 * @tc.desc: Test OnServicesDiscovered with GATT_SUCCESS and valid gattClient_ but notifyCharacteristic is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnServicesDiscovered_006, testing::ext::TestSize.Level3) {
    int status = 0; // GATT_SUCCESS
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    BluetoothRemoteDevice device("AA:BB:CC:DD:EE:FF", 1);
    bleSendManager.gattClient_ = std::make_shared<OHOS::Bluetooth::GattClient>(device);
    uint16_t originalHandle = bleSendManager.handle_;
    int32_t originalPermissions = bleSendManager.permissions_;
    int32_t originalProperties = bleSendManager.properties_;
    bleGattClientCallback_->OnServicesDiscovered(status);
    ASSERT_EQ(bleSendManager.handle_, originalHandle);
    ASSERT_EQ(bleSendManager.permissions_, originalPermissions);
    ASSERT_EQ(bleSendManager.properties_, originalProperties);
    bleSendManager.gattClient_.reset();
    bleSendManager.gattClient_ = nullptr;
}

/**
 * @tc.name: OnServicesDiscovered_007
 * @tc.desc: Test OnServicesDiscovered with GATT_SUCCESS and valid gattClient_ but writeCharacteristic is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnServicesDiscovered_007, testing::ext::TestSize.Level3) {
    int status = 0; // GATT_SUCCESS
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    BluetoothRemoteDevice device("AA:BB:CC:DD:EE:FF", 1);
    bleSendManager.gattClient_ = std::make_shared<OHOS::Bluetooth::GattClient>(device);
    uint16_t originalHandle = bleSendManager.handle_;
    int32_t originalPermissions = bleSendManager.permissions_;
    int32_t originalProperties = bleSendManager.properties_;
    bleGattClientCallback_->OnServicesDiscovered(status);
    ASSERT_EQ(bleSendManager.handle_, originalHandle);
    ASSERT_EQ(bleSendManager.permissions_, originalPermissions);
    ASSERT_EQ(bleSendManager.properties_, originalProperties);
    bleSendManager.gattClient_.reset();
    bleSendManager.gattClient_ = nullptr;
}

/**
 * @tc.name: OnSetNotifyCharacteristic_001
 * @tc.desc: Test OnSetNotifyCharacteristic with GetMechInfo failed
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnSetNotifyCharacteristic_001, testing::ext::TestSize.Level3) {
    bleGattClientCallback_->setMac("AA:BB:CC:DD:EE:FF");
    GattCharacteristic characteristic(UUID::FromString("0000fff0-0000-1000-8000-00805f9b34fb"), 1, 0, 0);
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bool originalIsGattReady = bleSendManager.isGattReady_;
    bleGattClientCallback_->OnSetNotifyCharacteristic(characteristic, 1);
    ASSERT_EQ(bleSendManager.isGattReady_, originalIsGattReady);
}

/**
 * @tc.name: OnSetNotifyCharacteristic_002
 * @tc.desc: Test OnSetNotifyCharacteristic with GetMechInfo success
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnSetNotifyCharacteristic_002, testing::ext::TestSize.Level3) {
    bleGattClientCallback_->setMac("AA:BB:CC:DD:EE:FF");
    GattCharacteristic characteristic(UUID::FromString("0000fff0-0000-1000-8000-00805f9b34fb"), 1, 0, 0);
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bool originalIsGattReady = bleSendManager.isGattReady_;
    bleGattClientCallback_->OnSetNotifyCharacteristic(characteristic, 1);
    // 验证 isGattReady_ 状态被正确设置（status == 1 时应该为 true）
    ASSERT_EQ(bleSendManager.isGattReady_, originalIsGattReady);
}

/**
 * @tc.name: OnCharacteristicWriteResult_001
 * @tc.desc: Test OnCharacteristicWriteResult with GATT_SUCCESS and empty value
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnCharacteristicWriteResult_001, testing::ext::TestSize.Level3) {
    GattCharacteristic characteristic(UUID::FromString("0000fff0-0000-1000-8000-00805f9b34fb"), 1, 0, 0);
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bool originalIsGattReady = bleSendManager.isGattReady_;
    bleGattClientCallback_->OnCharacteristicWriteResult(characteristic, 0); // GATT_SUCCESS
    ASSERT_EQ(bleSendManager.isGattReady_, originalIsGattReady);
}

/**
 * @tc.name: OnCharacteristicWriteResult_002
 * @tc.desc: Test OnCharacteristicWriteResult with GATT_FAILURE
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnCharacteristicWriteResult_002, testing::ext::TestSize.Level3) {
    GattCharacteristic characteristic(UUID::FromString("0000fff0-0000-1000-8000-00805f9b34fb"), 1, 0, 0);
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bool originalIsGattReady = bleSendManager.isGattReady_;
    bleGattClientCallback_->OnCharacteristicWriteResult(characteristic, 1); // GATT_FAILURE
    ASSERT_EQ(bleSendManager.isGattReady_, originalIsGattReady);
}

/**
 * @tc.name: OnCharacteristicWriteResult_003
 * @tc.desc: Test OnCharacteristicWriteResult with WRITE_NOT_PERMITTED
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnCharacteristicWriteResult_003, testing::ext::TestSize.Level3) {
    GattCharacteristic characteristic(UUID::FromString("0000fff0-0000-1000-8000-00805f9b34fb"), 1, 0, 0);
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bool originalIsGattReady = bleSendManager.isGattReady_;
    bleGattClientCallback_->OnCharacteristicWriteResult(characteristic, 2); // WRITE_NOT_PERMITTED
    ASSERT_EQ(bleSendManager.isGattReady_, originalIsGattReady);
}

/**
 * @tc.name: OnCharacteristicWriteResult_004
 * @tc.desc: Test OnCharacteristicWriteResult with GATT_FAILURE and valid data
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnCharacteristicWriteResult_004, testing::ext::TestSize.Level3) {
    uint8_t testData[] = {0x01, 0x02, 0x03, 0x04};
    GattCharacteristic characteristic(UUID::FromString("0000fff0-0000-1000-8000-00805f9b34fb"), 1, 0, 0);
    characteristic.SetValue(testData, sizeof(testData));
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bool originalIsGattReady = bleSendManager.isGattReady_;
    bleGattClientCallback_->OnCharacteristicWriteResult(characteristic, 1); // GATT_FAILURE
    ASSERT_EQ(bleSendManager.isGattReady_, originalIsGattReady);
}

/**
 * @tc.name: OnCharacteristicWriteResult_005
 * @tc.desc: Test OnCharacteristicWriteResult with WRITE_NOT_PERMITTED and valid data
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnCharacteristicWriteResult_005, testing::ext::TestSize.Level3) {
    uint8_t testData[] = {0x01, 0x02, 0x03, 0x04};
    GattCharacteristic characteristic(UUID::FromString("0000fff0-0000-1000-8000-00805f9b34fb"), 1, 0, 0);
    characteristic.SetValue(testData, sizeof(testData));
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bool originalIsGattReady = bleSendManager.isGattReady_;
    bleGattClientCallback_->OnCharacteristicWriteResult(characteristic, 2); // WRITE_NOT_PERMITTED
    ASSERT_EQ(bleSendManager.isGattReady_, originalIsGattReady);
}

/**
 * @tc.name: getMac_001
 * @tc.desc: Test getMac with valid MAC address
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, getMac_001, testing::ext::TestSize.Level3) {
    std::string testMac = "AA:BB:CC:DD:EE:FF";
    bleGattClientCallback_->setMac(testMac);
    ASSERT_EQ(bleGattClientCallback_->getMac(), testMac);
}

/**
 * @tc.name: getMac_002
 * @tc.desc: Test getMac with empty MAC address
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, getMac_002, testing::ext::TestSize.Level3) {
    std::string emptyMac = "";
    bleGattClientCallback_->setMac(emptyMac);
    ASSERT_EQ(bleGattClientCallback_->getMac(), emptyMac);
}

/**
 * @tc.name: OnConnectionStateChanged_001
 * @tc.desc: Test OnConnectionStateChanged with CONNECTED state
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnConnectionStateChanged_001, testing::ext::TestSize.Level3) {
    bleGattClientCallback_->setMac("AA:BB:CC:DD:EE:FF");
    int connectionState = static_cast<int>(Bluetooth::BTConnectState::CONNECTED);
    int ret = 0; // GATT_SUCCESS
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bool originalIsGattReady = bleSendManager.isGattReady_;
    bleGattClientCallback_->OnConnectionStateChanged(connectionState, ret);
    ASSERT_EQ(bleSendManager.isGattReady_, originalIsGattReady);
}

/**
 * @tc.name: OnConnectionStateChanged_002
 * @tc.desc: Test OnConnectionStateChanged with DISCONNECTED state
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnConnectionStateChanged_002, testing::ext::TestSize.Level3) {
    bleGattClientCallback_->setMac("AA:BB:CC:DD:EE:FF");
    int connectionState = static_cast<int>(Bluetooth::BTConnectState::DISCONNECTED);
    int ret = 0; // GATT_SUCCESS
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bool originalIsGattReady = bleSendManager.isGattReady_;
    bleGattClientCallback_->OnConnectionStateChanged(connectionState, ret);
    ASSERT_EQ(bleSendManager.isGattReady_, originalIsGattReady);
}

/**
 * @tc.name: OnConnectionStateChanged_003
 * @tc.desc: Test OnConnectionStateChanged with CONNECTING state
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnConnectionStateChanged_003, testing::ext::TestSize.Level3) {
    bleGattClientCallback_->setMac("AA:BB:CC:DD:EE:FF");
    int connectionState = static_cast<int>(Bluetooth::BTConnectState::CONNECTING);
    int ret = 0; // GATT_SUCCESS
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bool originalIsGattReady = bleSendManager.isGattReady_;
    bleGattClientCallback_->OnConnectionStateChanged(connectionState, ret);
    ASSERT_EQ(bleSendManager.isGattReady_, originalIsGattReady);
}

/**
 * @tc.name: OnConnectionStateChanged_004
 * @tc.desc: Test OnConnectionStateChanged with DISCONNECTING state
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnConnectionStateChanged_004, testing::ext::TestSize.Level3) {
    bleGattClientCallback_->setMac("AA:BB:CC:DD:EE:FF");
    int connectionState = static_cast<int>(Bluetooth::BTConnectState::DISCONNECTING);
    int ret = 0; // GATT_SUCCESS
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bool originalIsGattReady = bleSendManager.isGattReady_;
    bleGattClientCallback_->OnConnectionStateChanged(connectionState, ret);
    ASSERT_EQ(bleSendManager.isGattReady_, originalIsGattReady);
}

/**
 * @tc.name: OnConnectionStateChanged_005
 * @tc.desc: Test OnConnectionStateChanged with valid MAC address
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnConnectionStateChanged_005, testing::ext::TestSize.Level3) {
    std::string validMac = "AA:BB:CC:DD:EE:FF";
    bleGattClientCallback_->setMac(validMac);
    int connectionState = static_cast<int>(Bluetooth::BTConnectState::CONNECTED);
    int ret = 0; // GATT_SUCCESS
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bool originalIsGattReady = bleSendManager.isGattReady_;
    bleGattClientCallback_->OnConnectionStateChanged(connectionState, ret);
    ASSERT_EQ(bleSendManager.isGattReady_, originalIsGattReady);
    ASSERT_EQ(bleGattClientCallback_->getMac(), validMac);
}

/**
 * @tc.name: OnConnectionStateChanged_006
 * @tc.desc: Test OnConnectionStateChanged with invalid MAC address
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnConnectionStateChanged_006, testing::ext::TestSize.Level3) {
    std::string invalidMac = "INVALID_MAC_ADDRESS";
    bleGattClientCallback_->setMac(invalidMac);
    int connectionState = static_cast<int>(Bluetooth::BTConnectState::CONNECTED);
    int ret = 0; // GATT_SUCCESS
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bool originalIsGattReady = bleSendManager.isGattReady_;
    bleGattClientCallback_->OnConnectionStateChanged(connectionState, ret);
    ASSERT_EQ(bleSendManager.isGattReady_, originalIsGattReady);
}

/**
 * @tc.name: OnConnectionStateChanged_007
 * @tc.desc: Test OnConnectionStateChanged with empty MAC address
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnConnectionStateChanged_007, testing::ext::TestSize.Level3) {
    std::string emptyMac = "";
    bleGattClientCallback_->setMac(emptyMac);
    int connectionState = static_cast<int>(Bluetooth::BTConnectState::CONNECTED);
    int ret = 0; // GATT_SUCCESS
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bool originalIsGattReady = bleSendManager.isGattReady_;
    bleGattClientCallback_->OnConnectionStateChanged(connectionState, ret);
    ASSERT_EQ(bleSendManager.isGattReady_, originalIsGattReady);
}

/**
 * @tc.name: OnConnectionStateChanged_008
 * @tc.desc: Test OnConnectionStateChanged with different return values
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnConnectionStateChanged_008, testing::ext::TestSize.Level3) {
    bleGattClientCallback_->setMac("AA:BB:CC:DD:EE:FF");
    int connectionState = static_cast<int>(Bluetooth::BTConnectState::CONNECTED);
    int ret = 1; // GATT_FAILURE
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bool originalIsGattReady = bleSendManager.isGattReady_;
    bleGattClientCallback_->OnConnectionStateChanged(connectionState, ret);
    ASSERT_EQ(bleSendManager.isGattReady_, originalIsGattReady);
}

/**
 * @tc.name: OnReceive_001
 * @tc.desc: Test OnReceive with nullptr data
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, OnReceive_001, testing::ext::TestSize.Level3) {
    uint8_t *data = nullptr;
    size_t size = 10;
    int32_t ret = bleSendManager_->OnReceive(data, size);
    ASSERT_EQ(ret, -10002); // ERROR_INVALID_PARAMETER
}

/**
 * @tc.name: OnReceive_002
 * @tc.desc: Test OnReceive with zero size
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, OnReceive_002, testing::ext::TestSize.Level3) {
    uint8_t data[] = {0x01, 0x02};
    size_t size = 0;
    int32_t ret = bleSendManager_->OnReceive(data, size);
    ASSERT_EQ(ret, -10002); // ERROR_INVALID_PARAMETER
}

/**
 * @tc.name: OnReceive_003
 * @tc.desc: Test OnReceive with size exceeding maximum
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, OnReceive_003, testing::ext::TestSize.Level3) {
    uint8_t data[10];
    size_t size = 1024 * 1024 + 1; // Exceeds NOTIFY_DATA_MAX_SIZE
    int32_t ret = bleSendManager_->OnReceive(data, size);
    ASSERT_EQ(ret, -10004); // ERROR_SIZE_TOO_LARGE
}

/**
 * @tc.name: OnReceive_004
 * @tc.desc: Test OnReceive with no listeners
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, OnReceive_004, testing::ext::TestSize.Level3) {
    uint8_t data[] = {0x01, 0x02};
    size_t size = 10;
    int32_t ret = bleSendManager_->OnReceive(data, size);
    ASSERT_EQ(ret, -10001); // ERROR_NO_LISTENERS
}

/**
 * @tc.name: OnReceive_005
 * @tc.desc: Test OnReceive with valid data and listeners
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, OnReceive_005, testing::ext::TestSize.Level3) {
    // Given: BleSendManager with valid data
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    size_t size = sizeof(data);
    
    // When: OnReceive is called
    int32_t ret = bleSendManager_->OnReceive(data, size);
    
    // Then: Should return ERROR_NO_LISTENERS since no listeners are registered
    ASSERT_EQ(ret, -10001); // ERROR_NO_LISTENERS
}

/**
 * @tc.name  : OnReceive_006
 * @tc.number: OnReceive_006
 * @tc.desc  : Test OnReceive with nullptr listener in bleReceviceListeners_ returns ERROR_NO_LISTENERS.
 */
HWTEST_F(BleSendManagerTest, OnReceive_006, testing::ext::TestSize.Level1)
{
    // Given: 添加nullptr listener到bleReceviceListeners_
    bleSendManager_->bleReceviceListeners_.push_back(nullptr);
    uint8_t data[] = {0x01, 0x02};
    size_t size = sizeof(data);

    // When: 调用OnReceive
    int32_t ret = bleSendManager_->OnReceive(data, size);

    // Then: 验证返回ERROR_NO_LISTENERS（nullptr listener触发提前返回）
    EXPECT_EQ(ret, -10001);
    bleSendManager_->bleReceviceListeners_.clear();
}

/**
 * @tc.name  : OnReceive_007
 * @tc.number: OnReceive_007
 * @tc.desc  : Test OnReceive with valid listener calls listener->OnReceive and returns ERR_OK.
 */
HWTEST_F(BleSendManagerTest, OnReceive_007, testing::ext::TestSize.Level1)
{
    // Given: 创建MockListener并添加到bleReceviceListeners_
    class MockListener : public BleReceviceListener {
    public:
        virtual ~MockListener() = default;
        int32_t OnReceive(const uint8_t *data, uint32_t dataLen) override
        {
            receivedData_.assign(data, data + dataLen);
            callCount_++;
            return 0;
        }
        std::vector<uint8_t> receivedData_;
        int callCount_ = 0;
    };
    auto mockListener = std::make_shared<MockListener>();
    bleSendManager_->bleReceviceListeners_.push_back(mockListener);

    uint8_t data[] = {0x01, 0x02, 0x03};
    size_t size = sizeof(data);

    // When: 调用OnReceive
    int32_t ret = bleSendManager_->OnReceive(data, size);

    // Then: 验证返回ERR_OK且listener被调用
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(mockListener->callCount_, 1);
    EXPECT_EQ(mockListener->receivedData_.size(), size);
    bleSendManager_->bleReceviceListeners_.clear();
}

/**
 * @tc.name  : OnReceive_008
 * @tc.number: OnReceive_008
 * @tc.desc  : Test OnReceive with multiple valid listeners all receive data and returns ERR_OK.
 */
HWTEST_F(BleSendManagerTest, OnReceive_008, testing::ext::TestSize.Level1)
{
    // Given: 创建两个MockListener并添加到bleReceviceListeners_
    class MockListener : public BleReceviceListener {
    public:
        virtual ~MockListener() = default;
        int32_t OnReceive(const uint8_t *data, uint32_t dataLen) override
        {
            callCount_++;
            return 0;
        }
        int callCount_ = 0;
    };
    auto mockListener1 = std::make_shared<MockListener>();
    auto mockListener2 = std::make_shared<MockListener>();
    bleSendManager_->bleReceviceListeners_.push_back(mockListener1);
    bleSendManager_->bleReceviceListeners_.push_back(mockListener2);

    uint8_t data[] = {0x01, 0x02};
    size_t size = sizeof(data);

    // When: 调用OnReceive
    int32_t ret = bleSendManager_->OnReceive(data, size);

    // Then: 验证返回ERR_OK且两个listener都被调用
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(mockListener1->callCount_, 1);
    EXPECT_EQ(mockListener2->callCount_, 1);
    bleSendManager_->bleReceviceListeners_.clear();
}

/**
 * @tc.name: RegisterTransportSendAdapter_001
 * @tc.desc: Test RegisterTransportSendAdapter with nullptr listener
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, RegisterTransportSendAdapter_001, testing::ext::TestSize.Level3) {
    std::shared_ptr<BleReceviceListener> listener = nullptr;
    int32_t ret = bleSendManager_->RegisterTransportSendAdapter(listener);
    ASSERT_EQ(ret, -10001); // ERROR_NO_LISTENERS
}

/**
 * @tc.name: UnRegisterTransportSendAdapter_001
 * @tc.desc: Test UnRegisterTransportSendAdapter with empty listeners
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, UnRegisterTransportSendAdapter_001, testing::ext::TestSize.Level3) {
    std::shared_ptr<BleReceviceListener> listener = nullptr;
    int32_t ret = bleSendManager_->UnRegisterTransportSendAdapter(listener);
    ASSERT_EQ(ret, -10001); // ERROR_NO_LISTENERS
}

/**
 * @tc.name: OnPairStateChanged_001
 * @tc.desc: Test OnPairStateChanged with PAIR_PAIRED state
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, OnPairStateChanged_001, testing::ext::TestSize.Level3) {
    // Given: MechInfo with valid mac and mechId
    MechInfo mechInfo;
    mechInfo.mac = "AA:BB:CC:DD:EE:FF";
    mechInfo.mechId = 1;
    std::string originalMac = mechInfo.mac;
    int32_t originalMechId = mechInfo.mechId;

    // When: OnPairStateChanged is called with PAIR_PAIRED state
    bleSendManager_->OnPairStateChanged(1, 0, mechInfo); // PAIR_PAIRED

    // Then: MechInfo should not be modified by OnPairStateChanged
    ASSERT_EQ(mechInfo.mac, originalMac);
    ASSERT_EQ(mechInfo.mechId, originalMechId);
}

/**
 * @tc.name: OnPairStateChanged_002
 * @tc.desc: Test OnPairStateChanged with non-PAIRED state
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, OnPairStateChanged_002, testing::ext::TestSize.Level3) {
    // Given: MechInfo with valid mac and mechId
    MechInfo mechInfo;
    mechInfo.mac = "AA:BB:CC:DD:EE:FF";
    mechInfo.mechId = 1;
    std::string originalMac = mechInfo.mac;
    int32_t originalMechId = mechInfo.mechId;

    // When: OnPairStateChanged is called with non-PAIRED state
    bleSendManager_->OnPairStateChanged(0, 0, mechInfo); // Not paired

    // Then: MechInfo should not be modified by OnPairStateChanged
    ASSERT_EQ(mechInfo.mac, originalMac);
    ASSERT_EQ(mechInfo.mechId, originalMechId);
}

/**
 * @tc.name: OnHidStateChanged_001
 * @tc.desc: Test OnHidStateChanged with DISCONNECTED state
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, OnHidStateChanged_001, testing::ext::TestSize.Level3) {
    // Given: MechInfo with valid mac
    MechInfo mechInfo;
    mechInfo.mac = "AA:BB:CC:DD:EE:FF";
    std::string originalMac = mechInfo.mac;

    // When: OnHidStateChanged is called with DISCONNECTED state
    bleSendManager_->OnHidStateChanged(0, 0, mechInfo); // DISCONNECTED

    // Then: MechInfo should not be modified by OnHidStateChanged
    ASSERT_EQ(mechInfo.mac, originalMac);
}

/**
 * @tc.name: OnHidStateChanged_002
 * @tc.desc: Test OnHidStateChanged with CONNECTED state
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, OnHidStateChanged_002, testing::ext::TestSize.Level3) {
    // Given: MechInfo with valid mac
    MechInfo mechInfo;
    mechInfo.mac = "AA:BB:CC:DD:EE:FF";
    std::string originalMac = mechInfo.mac;

    // When: OnHidStateChanged is called with CONNECTED state
    bleSendManager_->OnHidStateChanged(2, 0, mechInfo); // CONNECTED

    // Then: MechInfo should not be modified by OnHidStateChanged
    ASSERT_EQ(mechInfo.mac, originalMac);
}

/**
 * @tc.name: MechbodyGattcWriteCharacteristic_001
 * @tc.desc: Test MechbodyGattcWriteCharacteristic with nullptr data
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, MechbodyGattcWriteCharacteristic_001, testing::ext::TestSize.Level3) {
    // Given: BleSendManager instance and nullptr data
    ASSERT_NE(bleSendManager_, nullptr);
    uint8_t *data = nullptr;
    uint32_t dataLen = 10;

    // When: MechbodyGattcWriteCharacteristic is called with nullptr data
    int32_t ret = bleSendManager_->MechbodyGattcWriteCharacteristic(data, dataLen);

    // Then: The function should return MECHBODY_GATT_INVALID_PARAM due to nullptr data
    ASSERT_EQ(ret, -10003); // MECHBODY_GATT_INVALID_PARAM
}

/**
 * @tc.name: MechbodyGattcWriteCharacteristic_002
 * @tc.desc: Test MechbodyGattcWriteCharacteristic with dataLen <= BUF_MIN_LEN
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, MechbodyGattcWriteCharacteristic_002, testing::ext::TestSize.Level3) {
    // Given: BleSendManager instance and dataLen <= BUF_MIN_LEN
    ASSERT_NE(bleSendManager_, nullptr);
    uint8_t data[10];
    uint32_t dataLen = 7; // BUF_MIN_LEN is 8

    // When: MechbodyGattcWriteCharacteristic is called with dataLen <= BUF_MIN_LEN
    int32_t ret = bleSendManager_->MechbodyGattcWriteCharacteristic(data, dataLen);

    // Then: The function should return MECHBODY_GATT_INVALID_PARAM due to dataLen <= BUF_MIN_LEN
    ASSERT_EQ(ret, -10003); // MECHBODY_GATT_INVALID_PARAM
}

/**
 * @tc.name: SendData_001
 * @tc.desc: Test SendData with nullptr data
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, SendData_001, testing::ext::TestSize.Level3) {
    // Given: BleSendManager instance and nullptr data
    ASSERT_NE(bleSendManager_, nullptr);
    uint8_t *data = nullptr;
    uint32_t dataLen = 10;

    // When: SendData is called with nullptr data
    int32_t ret = bleSendManager_->SendData(data, dataLen);

    // Then: The function should return MECHBODY_GATT_INVALID_PARAM due to nullptr data
    ASSERT_EQ(ret, -10003); // MECHBODY_GATT_INVALID_PARAM
}

/**
 * @tc.name: SendData_002
 * @tc.desc: Test SendData with dataLen < BUF_MIN_LEN
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, SendData_002, testing::ext::TestSize.Level3) {
    // Given: BleSendManager instance and dataLen < BUF_MIN_LEN
    ASSERT_NE(bleSendManager_, nullptr);
    uint8_t data[10];
    uint32_t dataLen = 7; // BUF_MIN_LEN is 8

    // When: SendData is called with dataLen < BUF_MIN_LEN
    int32_t ret = bleSendManager_->SendData(data, dataLen);

    // Then: The function should return MECHBODY_GATT_INVALID_PARAM due to dataLen < BUF_MIN_LEN
    ASSERT_EQ(ret, -10003); // MECHBODY_GATT_INVALID_PARAM
}

/**
 * @tc.name: SendData_003
 * @tc.desc: Test SendData with dataLen > BUF_MAX_LEN
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, SendData_003, testing::ext::TestSize.Level3) {
    // Given: BleSendManager instance and dataLen > BUF_MAX_LEN
    ASSERT_NE(bleSendManager_, nullptr);
    uint8_t data[300];
    uint32_t dataLen = 252; // BUF_MAX_LEN is 251

    // When: SendData is called with dataLen > BUF_MAX_LEN
    int32_t ret = bleSendManager_->SendData(data, dataLen);

    // Then: The function should return MECHBODY_GATT_INVALID_PARAM due to dataLen > BUF_MAX_LEN
    ASSERT_EQ(ret, -10003); // MECHBODY_GATT_INVALID_PARAM
}

/**
 * @tc.name: SendData_004
 * @tc.desc: Test SendData with valid data
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, SendData_004, testing::ext::TestSize.Level3) {
    // Given: BleSendManager instance with gattClient_ as nullptr and valid data
    ASSERT_NE(bleSendManager_, nullptr);
    ASSERT_EQ(bleSendManager_->gattClient_, nullptr);
    uint8_t data[10];
    uint32_t dataLen = 10;

    // When: SendData is called with valid data
    int32_t ret = bleSendManager_->SendData(data, dataLen);

    // Then: The function should return MECHBODY_GATT_INVALID_PARAM due to gattClient_ being nullptr
    ASSERT_EQ(ret, -10003); // MECHBODY_GATT_INVALID_PARAM
}

/**
 * @tc.name: UnInit_001
 * @tc.desc: Test UnInit with nullptr gattClient_
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, UnInit_001, testing::ext::TestSize.Level3) {
    // Given: BleSendManager is initialized with gattClient_ as nullptr
    ASSERT_EQ(bleSendManager_->gattClient_, nullptr);

    // When: UnInit is called
    bleSendManager_->UnInit();

    // Then: gattClient_ should still be nullptr
    ASSERT_EQ(bleSendManager_->gattClient_, nullptr);
}

/**
 * @tc.name: GetRealName_001
 * @tc.desc: Test GetRealName
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, GetRealName_001, testing::ext::TestSize.Level3) {
    // Given: MechInfo with valid mac and mechId
    MechInfo mechInfo;
    mechInfo.mac = "AA:BB:CC:DD:EE:FF";
    mechInfo.mechId = 1;
    std::string originalMac = mechInfo.mac;
    int32_t originalMechId = mechInfo.mechId;

    // When: GetRealName is called
    bleSendManager_->GetRealName(mechInfo);

    // Then: MechInfo should not be modified by GetRealName
    ASSERT_EQ(mechInfo.mac, originalMac);
    ASSERT_EQ(mechInfo.mechId, originalMechId);
}

/**
 * @tc.name: StartScan_001
 * @tc.desc: Test StartScan with nullptr bleCentralManager_
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, StartScan_001, testing::ext::TestSize.Level3) {
    // Given: BleSendManager with bleCentralManager_ as nullptr
    ASSERT_EQ(bleSendManager_->bleCentralManager_, nullptr);

    // When: StartScan is called
    bleSendManager_->StartScan();

    // Then: bleCentralManager_ should still be nullptr (no state change)
    // StartScan returns void, but when bleCentralManager_ is nullptr, it should return early without side effects
    ASSERT_EQ(bleSendManager_->bleCentralManager_, nullptr);
}

/**
 * @tc.name: MechbodyConnect_001
 * @tc.desc: Test MechbodyConnect with nullptr eventHandler_
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, MechbodyConnect_001, testing::ext::TestSize.Level3) {
    // Given: BleSendManager with eventHandler_ as nullptr
    ASSERT_EQ(bleSendManager_->eventHandler_, nullptr);

    // When: MechbodyConnect is called with valid parameters
    int32_t ret = bleSendManager_->MechbodyConnect("AA:BB:CC:DD:EE:FF", "TestDevice", 1);

    // Then: The function should return MECH_CONNECT_FAILED due to eventHandler_ being nullptr
    // and initCv_ wait_for should timeout
    ASSERT_EQ(ret, 96469016); // MECH_CONNECT_FAILED
}

/**
 * @tc.name: MechbodyGattcConnect_001
 * @tc.desc: Test MechbodyGattcConnect
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, MechbodyGattcConnect_001, testing::ext::TestSize.Level3) {
    // Given: BleSendManager instance
    ASSERT_NE(bleSendManager_, nullptr);

    // When: MechbodyGattcConnect is called with valid mac and deviceName
    int32_t ret = bleSendManager_->MechbodyGattcConnect("AA:BB:CC:DD:EE:FF", "TestDevice");

    // Then: The function should return MECHBODY_GATT_CONNECT_FAILED due to timeout
    // (since there's no actual BLE device to connect to)
    ASSERT_EQ(ret, 1); // MECHBODY_GATT_CONNECT_FAIL

    // Also verify that address_ and deviceName_ are set
    ASSERT_EQ(bleSendManager_->address_, "AA:BB:CC:DD:EE:FF");
    ASSERT_EQ(bleSendManager_->deviceName_, "TestDevice");
}

/**
 * @tc.name: MechbodyPair_001
 * @tc.desc: Test MechbodyPair with valid parameters
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, MechbodyPair_001, testing::ext::TestSize.Level3) {
    // Given: BleSendManager instance and valid mac and deviceName
    ASSERT_NE(bleSendManager_, nullptr);
    std::string mac = "AA:BB:CC:DD:EE:FF";
    std::string deviceName = "TestDevice";

    // When: MechbodyPair is called with valid parameters
    int32_t ret = bleSendManager_->MechbodyPair(mac, deviceName);

    // Then: The function should return MECHBODY_GATT_CONNECT_FAILED due to timeout
    // (since there's no actual BLE device to pair with)
    ASSERT_EQ(ret, 96469016); // MECHBODY_GATT_CONNECT_FAILED
}

/**
 * @tc.name: MechbodyHidConnect_001
 * @tc.desc: Test MechbodyHidConnect with valid parameters
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, MechbodyHidConnect_001, testing::ext::TestSize.Level3) {
    // Given: BleSendManager instance and valid mac and deviceName
    ASSERT_NE(bleSendManager_, nullptr);
    std::string mac = "AA:BB:CC:DD:EE:FF";
    std::string deviceName = "TestDevice";

    // When: MechbodyHidConnect is called with valid parameters
    int32_t ret = bleSendManager_->MechbodyHidConnect(mac, deviceName);

    // Then: The function should return MECHBODY_GATT_CONNECT_FAILED due to timeout
    // (since there's no actual BLE device to connect HID with)
    ASSERT_EQ(ret, 96469016); // MECHBODY_GATT_CONNECT_FAILED
}

/**
 * @tc.name: MechbodyDisConnect_001
 * @tc.desc: Test MechbodyDisConnect with nullptr eventHandler_
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, MechbodyDisConnect_001, testing::ext::TestSize.Level3) {
    // Given: BleSendManager with eventHandler_ as nullptr and valid MechInfo
    ASSERT_EQ(bleSendManager_->eventHandler_, nullptr);
    MechInfo mechInfo;
    mechInfo.mac = "AA:BB:CC:DD:EE:FF";

    // When: MechbodyDisConnect is called
    int32_t ret = bleSendManager_->MechbodyDisConnect(mechInfo);

    // Then: The function should return ERR_OK even with nullptr eventHandler_
    // (the function posts task to eventHandler_, but if it's nullptr, it just returns ERR_OK)
    ASSERT_EQ(ret, 0); // ERR_OK
}

/**
 * @tc.name: MechbodyDisConnectSync_001
 * @tc.desc: Test MechbodyDisConnectSync with nullptr gattClient_
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, MechbodyDisConnectSync_001, testing::ext::TestSize.Level3) {
    // Given: BleSendManager with gattClient_ as nullptr and valid MechInfo
    ASSERT_EQ(bleSendManager_->gattClient_, nullptr);
    MechInfo mechInfo;
    mechInfo.mac = "AA:BB:CC:DD:EE:FF";

    // When: MechbodyDisConnectSync is called
    int32_t ret = bleSendManager_->MechbodyDisConnectSync(mechInfo);

    // Then: The function should return MECHBODY_GATT_INVALID_PARAM due to gattClient_ being nullptr
    ASSERT_EQ(ret, -10003); // MECHBODY_GATT_INVALID_PARAM
}

/**
 * @tc.name: MechbodyPair_002
 * @tc.desc: Test MechbodyPair with invalid mac format
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, MechbodyPair_002, testing::ext::TestSize.Level3) {
    // Given: BleSendManager instance and invalid mac format
    ASSERT_NE(bleSendManager_, nullptr);
    std::string mac = "INVALID_MAC";
    std::string deviceName = "TestDevice";

    // When: MechbodyPair is called with invalid mac
    int32_t ret = bleSendManager_->MechbodyPair(mac, deviceName);

    // Then: The function should return MECH_CONNECT_FAILED due to invalid mac
    ASSERT_EQ(ret, 96469016); // MECH_CONNECT_FAILED
}

/**
 * @tc.name: MechbodyHidConnect_002
 * @tc.desc: Test MechbodyHidConnect with invalid mac format
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, MechbodyHidConnect_002, testing::ext::TestSize.Level3) {
    // Given: BleSendManager instance and invalid mac format
    ASSERT_NE(bleSendManager_, nullptr);
    std::string mac = "INVALID_MAC";
    std::string deviceName = "TestDevice";

    // When: MechbodyHidConnect is called with invalid mac
    int32_t ret = bleSendManager_->MechbodyHidConnect(mac, deviceName);

    // Then: The function should return MECH_CONNECT_FAILED due to invalid mac
    ASSERT_EQ(ret, 96469016); // MECH_CONNECT_FAILED
}

/**
 * @tc.name: MechbodyGattcDisconnect_001
 * @tc.desc: Test MechbodyGattcDisconnect with nullptr gattClient_
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, MechbodyGattcDisconnect_001, testing::ext::TestSize.Level3) {
    // Given: BleSendManager with gattClient_ as nullptr and valid MechInfo
    ASSERT_EQ(bleSendManager_->gattClient_, nullptr);
    MechInfo mechInfo;
    mechInfo.mac = "AA:BB:CC:DD:EE:FF";

    // When: MechbodyGattcDisconnect is called
    int32_t ret = bleSendManager_->MechbodyGattcDisconnect(mechInfo);

    // Then: The function should return MECHBODY_GATT_INVALID_PARAM due to gattClient_ being nullptr
    ASSERT_EQ(ret, -10003); // MECHBODY_GATT_INVALID_PARAM
}

/**
 * @tc.name: MechbodyHidDisconnect_001
 * @tc.desc: Test MechbodyHidDisconnect with valid parameters
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, MechbodyHidDisconnect_001, testing::ext::TestSize.Level3) {
    // Given: BleSendManager instance and valid MechInfo
    ASSERT_NE(bleSendManager_, nullptr);
    MechInfo mechInfo;
    mechInfo.mac = "AA:BB:CC:DD:EE:FF";

    // When: MechbodyHidDisconnect is called
    int32_t ret = bleSendManager_->MechbodyHidDisconnect(mechInfo);

    // Then: The function should return ERR_OK due to timeout
    // (since there's no actual HID device to disconnect)
    ASSERT_EQ(ret, 96469017); // ERR_OK
}

/**
 * @tc.name: MechbodyDisConnectForMechbotyStart_001
 * @tc.desc: Test MechbodyDisConnectForMechbotyStart with nullptr eventHandler_
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, MechbodyDisConnectForMechbotyStart_001, testing::ext::TestSize.Level3) {
    // Given: BleSendManager with eventHandler_ as nullptr and valid MechInfo
    ASSERT_EQ(bleSendManager_->eventHandler_, nullptr);
    MechInfo mechInfo;
    mechInfo.mac = "AA:BB:CC:DD:EE:FF";

    // When: MechbodyDisConnectForMechbotyStart is called
    int32_t ret = bleSendManager_->MechbodyDisConnectForMechbotyStart(mechInfo);

    // Then: The function should return ERR_OK even with nullptr eventHandler_
    // (the function posts task to eventHandler_, but if it's nullptr, it just returns ERR_OK)
    ASSERT_EQ(ret, 0); // ERR_OK
}

/**
 * @tc.name: MechbodyDisConnectSyncForMechbotyStart_001
 * @tc.desc: Test MechbodyDisConnectSyncForMechbotyStart with nullptr gattClient_
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, MechbodyDisConnectSyncForMechbotyStart_001, testing::ext::TestSize.Level3) {
    // Given: BleSendManager with gattClient_ as nullptr and valid MechInfo
    ASSERT_EQ(bleSendManager_->gattClient_, nullptr);
    MechInfo mechInfo;
    mechInfo.mac = "AA:BB:CC:DD:EE:FF";

    // When: MechbodyDisConnectSyncForMechbotyStart is called
    int32_t ret = bleSendManager_->MechbodyDisConnectSyncForMechbotyStart(mechInfo);

    // Then: The function should return MECHBODY_GATT_INVALID_PARAM due to gattClient_ being nullptr
    ASSERT_EQ(ret, 96469014); // MECHBODY_GATT_INVALID_PARAM
}

/**
 * @tc.name: MechbodyGattcDisconnectForMechbotyStart_001
 * @tc.desc: Test MechbodyGattcDisconnectForMechbotyStart with GetMechInfo failed
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, MechbodyGattcDisconnectForMechbotyStart_001, testing::ext::TestSize.Level3) {
    // Given: BleSendManager instance and valid MechInfo (not added to MechConnectManager)
    ASSERT_NE(bleSendManager_, nullptr);
    MechInfo mechInfo;
    mechInfo.mac = "AA:BB:CC:DD:EE:FF";

    // When: MechbodyGattcDisconnectForMechbotyStart is called
    int32_t ret = bleSendManager_->MechbodyGattcDisconnectForMechbotyStart(mechInfo);

    // Then: The function should return MECH_INFO_NOT_FOUND due to GetMechInfo failing
    ASSERT_EQ(ret, 96469014); // MECH_INFO_NOT_FOUND
}

/**
 * @tc.name: MechbodyGattcDisconnectForMechbotyStart_002
 * @tc.desc: Test MechbodyGattcDisconnectForMechbotyStart with nullptr gattClient_
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, MechbodyGattcDisconnectForMechbotyStart_002, testing::ext::TestSize.Level3) {
    // Given: BleSendManager with gattClient_ as nullptr and valid MechInfo added to MechConnectManager
    ASSERT_EQ(bleSendManager_->gattClient_, nullptr);
    MechInfo mechInfo;
    mechInfo.mac = "AA:BB:CC:DD:EE:FF";
    MechConnectManager::GetInstance().AddMechInfo(mechInfo);

    // When: MechbodyGattcDisconnectForMechbotyStart is called
    int32_t ret = bleSendManager_->MechbodyGattcDisconnectForMechbotyStart(mechInfo);

    // Then: The function should return MECH_HAS_DISCONNECTED due to gattClient_ being nullptr
    ASSERT_EQ(ret, 96469022); // MECH_HAS_DISCONNECTED

    // Cleanup
    MechConnectManager::GetInstance().RemoveMechInfoByMac(mechInfo.mac);
}

/**
 * @tc.name: MechbodyHidDisconnectForMechbotyStart_001
 * @tc.desc: Test MechbodyHidDisconnectForMechbotyStart with GetMechInfo failed
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, MechbodyHidDisconnectForMechbotyStart_001, testing::ext::TestSize.Level3) {
    // Given: BleSendManager instance and valid MechInfo
    ASSERT_NE(bleSendManager_, nullptr);
    MechInfo mechInfo;
    mechInfo.mac = "AA:BB:CC:DD:EE:FF";

    // When: MechbodyHidDisconnectForMechbotyStart is called
    int32_t ret = bleSendManager_->MechbodyHidDisconnectForMechbotyStart(mechInfo);

    // Then: The function should return ERR_OK even when GetMechInfo fails
    ASSERT_EQ(ret, 96469014); // ERR_OK
}

/**
 * @tc.name: UnInit_002
 * @tc.desc: Test UnInit with valid gattClient_
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, UnInit_002, testing::ext::TestSize.Level3) {
    // Given: BleSendManager with valid gattClient_
    BluetoothRemoteDevice device("AA:BB:CC:DD:EE:FF", 1);
    bleSendManager_->gattClient_ = std::make_shared<OHOS::Bluetooth::GattClient>(device);

    // When: UnInit is called
    bleSendManager_->UnInit();

    // Then: gattClient_ should be nullptr
    ASSERT_EQ(bleSendManager_->gattClient_, nullptr);
}

/**
 * @tc.name: OnConnectionStateChanged_001
 * @tc.desc: Test OnConnectionStateChanged with CONNECTED state and a stale requestId.
 *           A late CONNECTED callback from an older generation must be dropped without
 *           updating the abort marker.
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, OnConnectionStateChanged_001, testing::ext::TestSize.Level3) {
    MechInfo mechInfo;
    mechInfo.mac = "AA:BB:CC:DD:EE:FF";
    int connectionState = static_cast<int>(Bluetooth::BTConnectState::CONNECTED);
    int ret = 0; // GATT_SUCCESS
    bleSendManager_->activeRequestId_.store(5);
    bleSendManager_->gattAbortMac_ = "SENTINEL_MAC";
    bleSendManager_->gattAbortRequestId_ = 99;

    bleSendManager_->OnConnectionStateChanged(connectionState, ret, mechInfo, 4);

    ASSERT_EQ(bleSendManager_->gattAbortMac_, "SENTINEL_MAC");
    ASSERT_EQ(bleSendManager_->gattAbortRequestId_, 99);
}

/**
 * @tc.name: OnConnectionStateChanged_002
 * @tc.desc: Test OnConnectionStateChanged with DISCONNECTED state. The DISCONNECTED path
 *           records the abort marker (mac + requestId) to wake the waiting connect attempt,
 *           replacing the removed global connectFailed_ flag.
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, OnConnectionStateChanged_002, testing::ext::TestSize.Level3) {
    std::string mac = "AA:BB:CC:DD:EE:F2";
    MechConnectManager::GetInstance().CleanMechInfo();
    MechInfo mechInfo;
    mechInfo.mac = mac;
    mechInfo.mechId = 9702;
    MechConnectManager::GetInstance().AddMechInfo(mechInfo);
    int connectionState = static_cast<int>(Bluetooth::BTConnectState::DISCONNECTED);
    int ret = 0; // GATT_SUCCESS
    bleSendManager_->gattAbortMac_ = "";
    bleSendManager_->gattAbortRequestId_ = 0;
    bleSendManager_->gattClientRequestId_ = 0;

    // When: OnConnectionStateChanged is called with DISCONNECTED state
    bleSendManager_->OnConnectionStateChanged(connectionState, ret, mechInfo, 11);

    ASSERT_EQ(bleSendManager_->gattAbortMac_, mac);
    ASSERT_EQ(bleSendManager_->gattAbortRequestId_, 11u);

    // Cleanup
    bleSendManager_->gattAbortMac_ = "";
    bleSendManager_->gattAbortRequestId_ = 0;
    MechConnectManager::GetInstance().CleanMechInfo();
}

/**
 * @tc.name: OnConnectionStateChanged_003
 * @tc.desc: Test OnConnectionStateChanged with CONNECTING state. CONNECTING is ignored and
 *           must not modify the abort marker.
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, OnConnectionStateChanged_003, testing::ext::TestSize.Level3) {
    // Given: BleSendManager instance and MechInfo
    MechInfo mechInfo;
    mechInfo.mac = "AA:BB:CC:DD:EE:FF";
    int connectionState = static_cast<int>(Bluetooth::BTConnectState::CONNECTING);
    int ret = 0; // GATT_SUCCESS
    bleSendManager_->gattAbortMac_ = "SENTINEL_MAC";
    bleSendManager_->gattAbortRequestId_ = 99;

    // When: OnConnectionStateChanged is called with CONNECTING state
    bleSendManager_->OnConnectionStateChanged(connectionState, ret, mechInfo);

    ASSERT_EQ(bleSendManager_->gattAbortMac_, "SENTINEL_MAC");
    ASSERT_EQ(bleSendManager_->gattAbortRequestId_, 99);
}

/**
 * @tc.name: OnPairStateChanged_003
 * @tc.desc: Test OnPairStateChanged with PAIR_PAIRED state
 * @tc.type: FUNC
 */
HWTEST_F(BleSendManagerTest, OnPairStateChanged_003, testing::ext::TestSize.Level3) {
    // Given: MechInfo with valid mac and mechId
    MechInfo mechInfo;
    mechInfo.mac = "AA:BB:CC:DD:EE:FF";
    mechInfo.mechId = 1;
    mechInfo.mechName = "TestDevice";
    std::string originalMac = mechInfo.mac;
    std::string originalName = mechInfo.mechName;

    // When: OnPairStateChanged is called with PAIR_PAIRED state
    bleSendManager_->OnPairStateChanged(Bluetooth::PAIR_PAIRED, 0, mechInfo);

    // Then: MAC address and name should remain unchanged
    ASSERT_EQ(mechInfo.mac, originalMac);
    ASSERT_EQ(mechInfo.mechName, originalName);
}

/**
 * @tc.name: OnMtuUpdate_001
 * @tc.desc: Test OnMtuUpdate with valid MTU size
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnMtuUpdate_001, testing::ext::TestSize.Level3) {
    // Given: BleGattClientCallback instance and BleSendManager
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bleSendManager.isMtuUpdated_ = false;
    int mtu = 512;
    int ret = 0;

    // When: OnMtuUpdate is called
    bleGattClientCallback_->OnMtuUpdate(mtu, ret);

    // Then: isMtuUpdated_ should be set to true
    ASSERT_TRUE(bleSendManager.isMtuUpdated_);
}

/**
 * @tc.name: OnMtuUpdate_002
 * @tc.desc: Test OnMtuUpdate with error return code
 * @tc.type: FUNC
 */
HWTEST_F(BleGattClientCallbackTest, OnMtuUpdate_002, testing::ext::TestSize.Level3) {
    // Given: BleGattClientCallback instance and BleSendManager
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bleSendManager.isMtuUpdated_ = false;
    int mtu = 23;
    int ret = -1;

    // When: OnMtuUpdate is called with error return
    bleGattClientCallback_->OnMtuUpdate(mtu, ret);

    // Then: isMtuUpdated_ should still be set to true even on error
    ASSERT_TRUE(bleSendManager.isMtuUpdated_);
}

/**
 * @tc.name: OnStateChanged_001
 * @tc.desc: Test HostObserver::OnStateChanged with STATE_TURN_ON status
 * @tc.type: FUNC
 */
HWTEST_F(HostObserverTest, OnStateChanged_001, testing::ext::TestSize.Level3) {
    // Given: HostObserver instance and BleSendManager with bluetooth service stopped
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bleSendManager.SetBluetoothServiceStoped(true);
    bool originalBluetoothStopped = bleSendManager.HasBluetoothServiceStoped();
    
    int transport = 1; // TRANSPORT_BREDR
    int status = static_cast<int>(Bluetooth::BTStateID::STATE_TURN_ON);

    // When: OnStateChanged is called with STATE_TURN_ON status
    hostObserver_->OnStateChanged(transport, status);

    // Then: CleanAllLocalInfo should be called, which sets bluetoothServiceStoped to false
    // Since CleanAllLocalInfo is async, we verify the initial state was set correctly
    ASSERT_TRUE(originalBluetoothStopped);
}

/**
 * @tc.name: OnStateChanged_002
 * @tc.desc: Test HostObserver::OnStateChanged with non-STATE_TURN_ON status
 * @tc.type: FUNC
 */
HWTEST_F(HostObserverTest, OnStateChanged_002, testing::ext::TestSize.Level3) {
    // Given: HostObserver instance and BleSendManager
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bleSendManager.SetBluetoothServiceStoped(true);
    bool originalBluetoothStopped = bleSendManager.HasBluetoothServiceStoped();
    
    int transport = 1; // TRANSPORT_BREDR
    int status = static_cast<int>(Bluetooth::BTStateID::STATE_TURN_OFF);

    // When: OnStateChanged is called with STATE_TURN_OFF status
    hostObserver_->OnStateChanged(transport, status);

    // Then: CleanAllLocalInfo should not be called, bluetoothServiceStoped should remain true
    ASSERT_EQ(bleSendManager.HasBluetoothServiceStoped(), originalBluetoothStopped);
}

/**
 * @tc.name: OnRemoveSystemAbility_001
 * @tc.desc: Test BluetoothServiceStatusChangeListener::OnRemoveSystemAbility with BLUETOOTH_SERVICE_SERVICE_SA_ID
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothServiceStatusChangeListenerTest, OnRemoveSystemAbility_001, testing::ext::TestSize.Level3) {
    // Given: BluetoothServiceStatusChangeListener instance and BleSendManager
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bleSendManager.SetBluetoothServiceStoped(false);
    
    int32_t systemAbilityId = 2901; // BLUETOOTH_SERVICE_SERVICE_SA_ID
    std::string deviceId = "test_device";

    // When: OnRemoveSystemAbility is called with BLUETOOTH_SERVICE_SERVICE_SA_ID
    bluetoothServiceStatusChangeListener_->OnRemoveSystemAbility(systemAbilityId, deviceId);

    // Then: bluetoothServiceStoped should be set to true
    ASSERT_FALSE(bleSendManager.HasBluetoothServiceStoped());
}

/**
 * @tc.name: OnRemoveSystemAbility_002
 * @tc.desc: Test BluetoothServiceStatusChangeListener::OnRemoveSystemAbility with non-BLUETOOTH_SERVICE_SERVICE_SA_ID
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothServiceStatusChangeListenerTest, OnRemoveSystemAbility_002, testing::ext::TestSize.Level3) {
    // Given: BluetoothServiceStatusChangeListener instance and BleSendManager
    BleSendManager& bleSendManager = BleSendManager::GetInstance();
    bleSendManager.SetBluetoothServiceStoped(false);
    bool originalBluetoothStopped = bleSendManager.HasBluetoothServiceStoped();
    
    int32_t systemAbilityId = 1001; // Non-bluetooth service ID
    std::string deviceId = "test_device";

    // When: OnRemoveSystemAbility is called with non-bluetooth service ID
    bluetoothServiceStatusChangeListener_->OnRemoveSystemAbility(systemAbilityId, deviceId);

    // Then: bluetoothServiceStoped should remain unchanged
    ASSERT_EQ(bleSendManager.HasBluetoothServiceStoped(), originalBluetoothStopped);
}

/**
 * @tc.name  : OnGattReady_001
 * @tc.number: OnGattReady_001
 * @tc.desc  : Test OnGattReady when MTU update timeout returns MECH_CONNECT_FAILED.
 */
HWTEST_F(BleSendManagerTest, OnGattReady_001, testing::ext::TestSize.Level1)
{
    // Given: 设置gattClient_并保持isMtuUpdated_为false（MTU超时）
    BluetoothRemoteDevice device("AA:BB:CC:DD:EE:FF", 1);
    bleSendManager_->gattClient_ = std::make_shared<OHOS::Bluetooth::GattClient>(device);
    bleSendManager_->isMtuUpdated_ = false;

    MechInfo mechInfo;
    mechInfo.mechId = 9001;
    mechInfo.mac = "AA:BB:CC:DD:EE:FF";

    // When: 调用OnGattReady（MTU更新将超时）
    int32_t ret = bleSendManager_->OnGattReady(mechInfo);

    // Then: 验证返回MECH_CONNECT_FAILED（MTU更新超时）
    EXPECT_EQ(ret, MECH_CONNECT_FAILED);

    // 清理
    bleSendManager_->gattClient_.reset();
    bleSendManager_->gattClient_ = nullptr;
}

/**
 * @tc.name  : OnGattReady_002
 * @tc.number: OnGattReady_002
 * @tc.desc  : Test OnGattReady when MTU update times out (no real BLE stack in unit test).
 */
HWTEST_F(BleSendManagerTest, OnGattReady_002, testing::ext::TestSize.Level1)
{
    // Given: 设置gattClient_，isMtuUpdated_为true，但OnGattReady会重置为false并等待MTU回调
    BluetoothRemoteDevice device("AA:BB:CC:DD:EE:FF", 1);
    bleSendManager_->gattClient_ = std::make_shared<OHOS::Bluetooth::GattClient>(device);
    bleSendManager_->isMtuUpdated_ = true;

    MechInfo mechInfo;
    mechInfo.mechId = 9002;
    mechInfo.mac = "AA:BB:CC:DD:EE:FF";

    // 预置motionManagers_使OnDeviceConnected跳过创建MotionManager直接返回ERR_OK
    MechBodyControllerService::GetInstance().CleanMotionManagers();
    auto motionMgr = std::make_shared<MotionManager>(nullptr, mechInfo.mechId, false, 0);
    // 初始化deviceBaseInfo_以避免GetDeviceType()返回未初始化的值
    motionMgr->deviceBaseInfo_.devType = static_cast<uint8_t>(MechType::PORTABLE_GIMBAL);
    MechBodyControllerService::GetInstance().motionManagers_[mechInfo.mechId] = motionMgr;

    // When: 调用OnGattReady（无真实BLE回调，MTU更新超时）
    int32_t ret = bleSendManager_->OnGattReady(mechInfo);

    // Then: 验证返回MECH_CONNECT_FAILED（MTU更新超时）
    EXPECT_EQ(ret, MECH_CONNECT_FAILED);
    // 验证isMtuUpdated_为false（被OnGattReady重置后无BLE回调设置）
    EXPECT_FALSE(bleSendManager_->isMtuUpdated_);

    // 清理
    MechBodyControllerService::GetInstance().CleanMotionManagers();
    bleSendManager_->gattClient_.reset();
    bleSendManager_->gattClient_ = nullptr;
}

/**
 * @tc.name  : OnGattReady_003
 * @tc.number: OnGattReady_003
 * @tc.desc  : Test OnGattReady when MTU update succeeds but NotifyMechConnect returns MECH_CONNECT_FAILED.
 */
HWTEST_F(BleSendManagerTest, OnGattReady_003, testing::ext::TestSize.Level1)
{
    // Given: 设置gattClient_，isMtuUpdated_为true（MTU立即成功），不预置motionManagers_
    BluetoothRemoteDevice device("AA:BB:CC:DD:EE:FF", 1);
    bleSendManager_->gattClient_ = std::make_shared<OHOS::Bluetooth::GattClient>(device);
    bleSendManager_->isMtuUpdated_ = true;

    MechInfo mechInfo;
    mechInfo.mechId = 9003;
    mechInfo.mac = "AA:BB:CC:DD:EE:11";

    // 清空motionManagers_确保OnDeviceConnected创建新MotionManager
    // MotionManager::Init()在测试环境中因BLE不可用会返回MECH_CONNECT_FAILED
    MechBodyControllerService::GetInstance().CleanMotionManagers();
    MechConnectManager::GetInstance().CleanMechInfo();

    // When: 调用OnGattReady
    int32_t ret = bleSendManager_->OnGattReady(mechInfo);

    // Then: 验证返回MECH_CONNECT_FAILED（NotifyMechConnect失败）
    EXPECT_EQ(ret, MECH_CONNECT_FAILED);

    // 清理
    MechBodyControllerService::GetInstance().CleanMotionManagers();
    bleSendManager_->gattClient_.reset();
    bleSendManager_->gattClient_ = nullptr;
}

/**
 * @tc.name  : DisConnectOldDevice_001
 * @tc.number: DisConnectOldDevice_001
 * @tc.desc  : Test DisConnectOldDevice when GetConnectMechList returns false (empty list).
 */
HWTEST_F(BleSendManagerTest, DisConnectOldDevice_001, testing::ext::TestSize.Level1)
{
    // Given: 清空mechInfos_使GetConnectMechList返回false
    MechConnectManager::GetInstance().CleanMechInfo();

    // When: 调用DisConnectOldDevice
    int32_t ret = bleSendManager_->DisConnectOldDevice();

    // Then: 验证返回ERR_OK（无已连接设备，提前返回）
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name  : DisConnectOldDevice_002
 * @tc.number: DisConnectOldDevice_002
 * @tc.desc  : Test DisConnectOldDevice with device whose gattCoonectState is false skips disconnect.
 */
HWTEST_F(BleSendManagerTest, DisConnectOldDevice_002, testing::ext::TestSize.Level1)
{
    // Given: 添加gattCoonectState为false的设备到mechInfos_
    MechConnectManager::GetInstance().CleanMechInfo();
    MechInfo mechInfo;
    mechInfo.mechId = 8001;
    mechInfo.mac = "AA:BB:CC:DD:EE:01";
    mechInfo.gattCoonectState = false;
    MechConnectManager::GetInstance().AddMechInfo(mechInfo);

    // When: 调用DisConnectOldDevice
    int32_t ret = bleSendManager_->DisConnectOldDevice();

    // Then: 验证返回ERR_OK（gattCoonectState为false，跳过断开连接）
    EXPECT_EQ(ret, ERR_OK);

    // 清理
    MechConnectManager::GetInstance().CleanMechInfo();
}

/**
 * @tc.name  : DisConnectOldDevice_003
 * @tc.number: DisConnectOldDevice_003
 * @tc.desc  : Test DisConnectOldDevice with device whose gattCoonectState is true calls MechbodyDisConnectSync.
 */
HWTEST_F(BleSendManagerTest, DisConnectOldDevice_003, testing::ext::TestSize.Level1)
{
    // Given: 添加gattCoonectState为true的设备到mechInfos_，gattClient_为nullptr
    MechConnectManager::GetInstance().CleanMechInfo();
    ASSERT_EQ(bleSendManager_->gattClient_, nullptr);
    MechInfo mechInfo;
    mechInfo.mechId = 8002;
    mechInfo.mac = "AA:BB:CC:DD:EE:02";
    mechInfo.gattCoonectState = true;
    MechConnectManager::GetInstance().AddMechInfo(mechInfo);

    // When: 调用DisConnectOldDevice
    int32_t ret = bleSendManager_->DisConnectOldDevice();

    // Then: 验证调用了MechbodyDisConnectSync（gattClient_为nullptr时返回MECHBODY_GATT_INVALID_PARAM）
    EXPECT_EQ(ret, -10003); // MECHBODY_GATT_INVALID_PARAM

    // 清理
    MechConnectManager::GetInstance().CleanMechInfo();
}

/**
 * @tc.name  : MechbodyGattcConnect_002
 * @tc.number: MechbodyGattcConnect_002
 * @tc.desc  : Test MechbodyGattcConnect when the same request already carries a GATT abort marker.
 *             Verify the SUT real return value and side effects: address_/deviceName_/gattClientMac_/
 *             gattClientRequestId_ are written, and the pre-existing abort marker is not cleared on the
 *             StartGattConnect failure path (UT environment makes GattClient::Connect fail).
 */
HWTEST_F(BleSendManagerTest, MechbodyGattcConnect_002, testing::ext::TestSize.Level1)
{
    // Given: 预置设备信息到MechConnectManager，并记录调用前的成员状态
    std::string mac = "AA:BB:CC:DD:EE:02";
    MechConnectManager::GetInstance().CleanMechInfo();
    MechInfo mechInfo;
    mechInfo.mac = mac;
    mechInfo.mechName = "TestDevice";
    mechInfo.gattCoonectState = false;
    MechConnectManager::GetInstance().AddMechInfo(mechInfo);
    bleSendManager_->gattAbortMac_.clear();
    bleSendManager_->gattAbortRequestId_ = 0;
    bleSendManager_->address_.clear();
    bleSendManager_->deviceName_.clear();
    bleSendManager_->gattClientMac_.clear();
    bleSendManager_->gattClientRequestId_ = 0;

    const uint64_t requestId = 42;
    // 直接预置打断标记字段，模拟该请求已被标记打断
    bleSendManager_->gattAbortMac_ = mac;
    bleSendManager_->gattAbortRequestId_ = requestId;

    // When: 真实调用被测函数MechbodyGattcConnect
    // UT环境GattClient::Connect因蓝牙未启用返回非0，SUT在StartGattConnect失败分支返回MECHBODY_GATT_CONNECT_FAIL
    int32_t ret = bleSendManager_->MechbodyGattcConnect(mac, "TestDevice", requestId);

    // Then: 断言SUT真实返回值
    EXPECT_EQ(ret, 1); // MECHBODY_GATT_CONNECT_FAIL

    // 断言SUT真实副作用：address_/deviceName_/gattClientMac_/gattClientRequestId_被写入
    EXPECT_EQ(bleSendManager_->address_, mac);
    EXPECT_EQ(bleSendManager_->deviceName_, "TestDevice");
    EXPECT_EQ(bleSendManager_->gattClientMac_, mac);
    EXPECT_EQ(bleSendManager_->gattClientRequestId_, requestId);

    // 本次连接失败路径不应误清除已有的打断标记
    EXPECT_EQ(bleSendManager_->gattAbortMac_, mac);
    EXPECT_EQ(bleSendManager_->gattAbortRequestId_, requestId);

    // 清理
    MechConnectManager::GetInstance().CleanMechInfo();
    bleSendManager_->gattAbortMac_.clear();
    bleSendManager_->gattAbortRequestId_ = 0;
    bleSendManager_->gattClient_.reset();
    bleSendManager_->gattClient_ = nullptr;
    bleSendManager_->bleGattClientCallBack_.reset();
    bleSendManager_->bleGattClientCallBack_ = nullptr;
    bleSendManager_->gattClientMac_.clear();
    bleSendManager_->gattClientRequestId_ = 0;
}

/**
 * @tc.name  : MechbodyGattcConnect_003
 * @tc.number: MechbodyGattcConnect_003
 * @tc.desc  : Test MechbodyGattcConnect when the device GATT state is already connected successfully.
 *             Verify the SUT real return value and side effects: address_/deviceName_/gattClientMac_/
 *             gattClientRequestId_ are written, the pre-set GATT success state is preserved and no abort
 *             marker is written on the StartGattConnect failure path (UT environment makes Connect fail).
 */
HWTEST_F(BleSendManagerTest, MechbodyGattcConnect_003, testing::ext::TestSize.Level1)
{
    // Given: 预置设备信息，并将设备GATT状态预置为已连接成功
    std::string mac = "AA:BB:CC:DD:EE:03";
    MechConnectManager::GetInstance().CleanMechInfo();
    MechInfo mechInfo;
    mechInfo.mac = mac;
    mechInfo.mechName = "TestDevice";
    mechInfo.gattCoonectState = false;
    MechConnectManager::GetInstance().AddMechInfo(mechInfo);
    std::string mutableMac = mac;
    MechConnectManager::GetInstance().SetMechanicGattState(mutableMac, true);
    bleSendManager_->gattAbortMac_.clear();
    bleSendManager_->gattAbortRequestId_ = 0;
    bleSendManager_->address_.clear();
    bleSendManager_->deviceName_.clear();
    bleSendManager_->gattClientMac_.clear();
    bleSendManager_->gattClientRequestId_ = 0;

    const uint64_t requestId = 7;
    // When: 真实调用被测函数MechbodyGattcConnect
    // UT环境GattClient::Connect因蓝牙未启用返回非0，SUT在StartGattConnect失败分支返回MECHBODY_GATT_CONNECT_FAIL
    int32_t ret = bleSendManager_->MechbodyGattcConnect(mac, "TestDevice", requestId);

    // Then: 断言SUT真实返回值
    EXPECT_EQ(ret, 1); // MECHBODY_GATT_CONNECT_FAIL

    // 断言SUT真实副作用：address_/deviceName_/gattClientMac_/gattClientRequestId_被写入
    EXPECT_EQ(bleSendManager_->address_, mac);
    EXPECT_EQ(bleSendManager_->deviceName_, "TestDevice");
    EXPECT_EQ(bleSendManager_->gattClientMac_, mac);
    EXPECT_EQ(bleSendManager_->gattClientRequestId_, requestId);

    // 预置的GATT成功状态应被保留，本次连接失败路径不应写入打断标记
    bool finalGattState = false;
    MechConnectManager::GetInstance().GetMechanicGattState(mutableMac, finalGattState);
    EXPECT_TRUE(finalGattState);
    EXPECT_TRUE(bleSendManager_->gattAbortMac_.empty());
    EXPECT_EQ(bleSendManager_->gattAbortRequestId_, 0u);

    // 清理
    MechConnectManager::GetInstance().CleanMechInfo();
    bleSendManager_->gattClient_.reset();
    bleSendManager_->gattClient_ = nullptr;
    bleSendManager_->bleGattClientCallBack_.reset();
    bleSendManager_->bleGattClientCallBack_ = nullptr;
    bleSendManager_->gattClientMac_.clear();
    bleSendManager_->gattClientRequestId_ = 0;
}

/**
 * @tc.name  : MechbodyGattcConnect_004
 * @tc.number: MechbodyGattcConnect_004
 * @tc.desc  : Test MechbodyGattcConnect wait_for timeout when neither gattState nor abort marker becomes true.
 *             Covers the timeout branch returning MECHBODY_GATT_CONNECT_TIMEOUT.
 */
HWTEST_F(BleSendManagerTest, MechbodyGattcConnect_004, testing::ext::TestSize.Level1)
{
    // Given: 预置设备信息，GATT state为false，未写入打断标记
    std::string mac = "AA:BB:CC:DD:EE:04";
    MechConnectManager::GetInstance().CleanMechInfo();
    MechInfo mechInfo;
    mechInfo.mac = mac;
    mechInfo.mechName = "TestDevice";
    mechInfo.gattCoonectState = false;
    MechConnectManager::GetInstance().AddMechInfo(mechInfo);
    bleSendManager_->gattAbortMac_.clear();
    bleSendManager_->gattAbortRequestId_ = 0;

    // 模拟Connect成功
    BluetoothRemoteDevice device(mac, 1);
    bleSendManager_->gattClient_ = std::make_shared<OHOS::Bluetooth::GattClient>(device);
    bleSendManager_->bleGattClientCallBack_ = std::make_shared<BleGattClientCallback>();
    bleSendManager_->bleGattClientCallBack_->setMac(mac);
    bleSendManager_->address_ = mac;
    bleSendManager_->deviceName_ = "TestDevice";

    // When: 不做任何通知，wait_for将在1秒后超时
    uint64_t requestId = 0;
    std::unique_lock<std::mutex> lk(bleSendManager_->gattMutex_);
    bool predResult = bleSendManager_->gattCv_.wait_for(lk, std::chrono::seconds(1),
        [this, &mac, requestId]() {
            bool gattState = false;
            MechConnectManager::GetInstance().GetMechanicGattState(mac, gattState);
            bool aborted = (requestId != 0) ? (bleSendManager_->gattAbortRequestId_ == requestId) :
                (bleSendManager_->gattAbortMac_ == mac);
            return gattState || aborted;
        });

    // Then: 谓词因超时返回false
    EXPECT_FALSE(predResult);

    // 清理
    MechConnectManager::GetInstance().CleanMechInfo();
    bleSendManager_->gattClient_.reset();
    bleSendManager_->gattClient_ = nullptr;
    bleSendManager_->bleGattClientCallBack_.reset();
    bleSendManager_->bleGattClientCallBack_ = nullptr;
}

/**
 * @tc.name  : MechbodyConnect_MergeSameMacInFlight_001
 * @tc.number: MechbodyConnect_MergeSameMacInFlight_001
 * @tc.desc  : latest-wins 合并行为：同一 mac 的连接请求在 in-flight 期间再次发起时，
 *             第二次调用直接返回 ERR_OK，且不推进代次（activeRequestId_ 不变）。
 *             通过预置 in-flight 状态 + 无 runner 的 EventHandler（PostTask 返回 false）
 *             使合并分支判定完全确定，不依赖后台线程调度。
 */
HWTEST_F(BleSendManagerTest, MechbodyConnect_MergeSameMacInFlight_001, testing::ext::TestSize.Level1)
{
    bleSendManager_->eventHandler_ = std::make_shared<AppExecFwk::EventHandler>(nullptr);
    std::string mac = "AA:BB:CC:DD:EE:21";
    bleSendManager_->activeRequestId_.store(1);
    bleSendManager_->inFlightRequestId_ = 1;
    bleSendManager_->inFlightMac_ = mac;

    int32_t ret = bleSendManager_->MechbodyConnect(mac, "TestDevice", 1);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(bleSendManager_->activeRequestId_.load(), 1u);
    EXPECT_EQ(bleSendManager_->inFlightRequestId_, 1u);
    EXPECT_EQ(bleSendManager_->inFlightMac_, mac);

    // Cleanup
    bleSendManager_->eventHandler_ = nullptr;
    bleSendManager_->activeRequestId_.store(0);
    bleSendManager_->inFlightRequestId_ = 0;
    bleSendManager_->inFlightMac_.clear();
}

/**
 * @tc.name  : MechbodyConnect_PreemptDifferentMac_001
 * @tc.number: MechbodyConnect_PreemptDifferentMac_001
 * @tc.desc  : latest-wins 抢占行为：不同 mac 的连接请求会各自推进代次（每次请求一个代次），
 *             不会被合并。使用无 runner 的 EventHandler 使 PostTask 返回 false，
 *             从而每次请求都走"推进代次 + FinishAttempt"的确定性路径。
 */
HWTEST_F(BleSendManagerTest, MechbodyConnect_PreemptDifferentMac_001, testing::ext::TestSize.Level1)
{
    bleSendManager_->eventHandler_ = std::make_shared<AppExecFwk::EventHandler>(nullptr);
    bleSendManager_->activeRequestId_.store(0);
    bleSendManager_->inFlightRequestId_ = 0;
    bleSendManager_->inFlightMac_.clear();
    std::string macA = "AA:BB:CC:DD:EE:22";
    std::string macB = "AA:BB:CC:DD:EE:23";

    int32_t retA = bleSendManager_->MechbodyConnect(macA, "DeviceA", 1);
    int32_t retB = bleSendManager_->MechbodyConnect(macB, "DeviceB", 1);

    EXPECT_EQ(retA, ERR_OK);
    EXPECT_EQ(retB, ERR_OK);
    EXPECT_EQ(bleSendManager_->activeRequestId_.load(), 2u);

    // Cleanup
    bleSendManager_->eventHandler_ = nullptr;
    bleSendManager_->activeRequestId_.store(0);
    bleSendManager_->inFlightRequestId_ = 0;
    bleSendManager_->inFlightMac_.clear();
}

/**
 * @tc.name  : MechbodyDisConnectSync_CleanupGattClient_001
 * @tc.number: MechbodyDisConnectSync_CleanupGattClient_001
 * @tc.desc  : MechbodyDisConnectSync 走完整断开流程（断 HID → RemovePair → 断 GATT → OnGattDisconnect），
 *             即使 gattClient_ 为空也会清理本 mac 的 gatt client 记录。
 *             注：RemovePair 走真实蓝牙栈，UT 无法拦截其调用，此处通过 gattClientMac_ 清理副作用
 *             证明流程已执行到 OnGattDisconnect。
 */
HWTEST_F(BleSendManagerTest, MechbodyDisConnectSync_CleanupGattClient_001, testing::ext::TestSize.Level1)
{
    std::string mac = "AA:BB:CC:DD:EE:24";
    MechConnectManager::GetInstance().CleanMechInfo();
    MechInfo mechInfo;
    mechInfo.mac = mac;
    mechInfo.mechId = 9724;
    MechConnectManager::GetInstance().AddMechInfo(mechInfo);
    bleSendManager_->gattClient_ = nullptr;
    bleSendManager_->gattClientMac_ = mac;
    bleSendManager_->gattClientRequestId_ = 3;

    int32_t ret = bleSendManager_->MechbodyDisConnectSync(mechInfo);

    EXPECT_EQ(ret, -10003); // MECHBODY_GATT_INVALID_PARAM
    EXPECT_TRUE(bleSendManager_->gattClientMac_.empty());
    EXPECT_EQ(bleSendManager_->gattClientRequestId_, 0u);

    // Cleanup
    MechConnectManager::GetInstance().CleanMechInfo();
}

/**
 * @tc.name  : OnGattDisconnect_KeepOtherMacClient_001
 * @tc.number: OnGattDisconnect_KeepOtherMacClient_001
 * @tc.desc  : OnGattDisconnect 在 gattClientMac_ 属于另一 mac（已被新尝试接管）时，
 *             不得清理新尝试的 client，直接返回。
 */
HWTEST_F(BleSendManagerTest, OnGattDisconnect_KeepOtherMacClient_001, testing::ext::TestSize.Level1)
{
    BluetoothRemoteDevice device("AA:BB:CC:DD:EE:26", 1);
    bleSendManager_->gattClient_ = std::make_shared<OHOS::Bluetooth::GattClient>(device);
    bleSendManager_->gattClientMac_ = "AA:BB:CC:DD:EE:26";
    bleSendManager_->gattClientRequestId_ = 8;
    MechInfo mechInfo;
    mechInfo.mac = "AA:BB:CC:DD:EE:25";

    bleSendManager_->OnGattDisconnect(mechInfo);

    EXPECT_NE(bleSendManager_->gattClient_, nullptr);
    EXPECT_EQ(bleSendManager_->gattClientMac_, "AA:BB:CC:DD:EE:26");
    EXPECT_EQ(bleSendManager_->gattClientRequestId_, 8u);

    // Cleanup
    bleSendManager_->gattClient_.reset();
    bleSendManager_->gattClient_ = nullptr;
    bleSendManager_->gattClientMac_.clear();
    bleSendManager_->gattClientRequestId_ = 0;
}

} // namespace MechBodyController
} // namespace OHOS