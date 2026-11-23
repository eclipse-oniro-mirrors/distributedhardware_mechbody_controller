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
#include "mcmotionmanagertwentytwo_fuzzer.h"
#include "mc_motion_manager.h"
#include "mc_connect_manager.h"
#include "mechbody_controller_types.h"
#include "mechbody_controller_enums.h"
#include "mc_send_adapter.h"
#include "mock_transport_send_adapter.h"
#include "mechbody_controller_log.h"
#include <memory>

namespace {
constexpr int32_t TEST_MECH_ID = 1;
}

using namespace OHOS;
using namespace OHOS::MechBodyController;

namespace {
const std::string TAG = "MotionManagerTwentyTwoFuzz";

std::shared_ptr<MotionManager> g_motionManager = nullptr;
std::shared_ptr<MockTransportSendAdapter> g_mockAdapter = nullptr;

void InitMotionManager()
{
    if (g_motionManager == nullptr) {
        g_mockAdapter = std::make_shared<MockTransportSendAdapter>();
        g_motionManager = std::make_shared<MotionManager>(g_mockAdapter, TEST_MECH_ID, false, 0x00000000);
        g_motionManager->Init();
        g_motionManager->RegisterAbilityStateChangeListener();
        g_motionManager->UnRegisterAbilityStateChangeListener();
        MechInfo testMech;
        testMech.mechId = TEST_MECH_ID;
        testMech.mechType = MechType::PORTABLE_GIMBAL;
        testMech.mac = "AA:BB:CC:DD:EE:FF";
        testMech.state = AttachmentState::ATTACHED;
        testMech.deviceIdentifier = 0x00000000;
        MechConnectManager::GetInstance().AddMechInfo(testMech);
        MechConnectManager::GetInstance().NotifyMechState(TEST_MECH_ID, true);
    }
}

void FuzzGetMechId(FuzzedDataProvider &provider)
{
    InitMotionManager();
    (void)g_motionManager->GetMechId();
    (void)provider.ConsumeBool();
}

void FuzzIsFirstConnect(FuzzedDataProvider &provider)
{
    InitMotionManager();
    (void)g_motionManager->GetIsFirstConnect();
    bool isFirstConnect = provider.ConsumeBool();
    g_motionManager->SetIsFirstConnect(isFirstConnect);
    (void)g_motionManager->GetIsFirstConnect();
}

void FuzzAutoCentering(FuzzedDataProvider &provider)
{
    InitMotionManager();
    bool isAutoCentering = provider.ConsumeBool();
    g_motionManager->SetAutoCentering(isAutoCentering);
}

void FuzzDfxConnectDelay(FuzzedDataProvider &provider)
{
    InitMotionManager();
    uint32_t dfxDelay = provider.ConsumeIntegral<uint32_t>();
    g_motionManager->SetDfxConnectDelay(dfxDelay);
}

void FuzzGetStrackingTime(FuzzedDataProvider &provider)
{
    InitMotionManager();
    (void)g_motionManager->GetStrackingTime();
    (void)provider.ConsumeBool();
}

void FuzzGetDfxInfo(FuzzedDataProvider &provider)
{
    InitMotionManager();
    (void)g_motionManager->GetDfxInfo();
    (void)provider.ConsumeBool();
}

void FuzzIsNeedSendTrackingData(FuzzedDataProvider &provider)
{
    InitMotionManager();
    static const ActionType VALID_ACTIONS[] = {
        ActionType::LANDSCAPE_PORTRAIT_SWITCH, ActionType::PATROL_MODE, ActionType::GREET_MODE,
        ActionType::HEAD_UP, ActionType::HEAD_UP_SLIGHTLY, ActionType::EYE_LEVEL,
        ActionType::HEAD_DOWN_SLIGHTLY, ActionType::HEAD_DOWN, ActionType::HEAD_WIGGLE,
        ActionType::NOD, ActionType::HEAD_SHAKE, ActionType::HEAD_TURN_TO_BASE,
        ActionType::BASE_TURN_TO_HEAD, ActionType::HAPPY, ActionType::ANGRY,
        ActionType::SAD, ActionType::SCARED, ActionType::DANCE, ActionType::ACTING_CUTE,
        ActionType::CELEBRATE, ActionType::WAKEUP, ActionType::SLEEP,
        ActionType::LOW_POWER, ActionType::THINKING,
    };
    uint8_t actionIdx = provider.ConsumeIntegral<uint8_t>() %
        (sizeof(VALID_ACTIONS) / sizeof(VALID_ACTIONS[0]));
    (void)g_motionManager->isNeedSendTrackingData(VALID_ACTIONS[actionIdx]);
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return 0;
    }
    FuzzedDataProvider provider(data, size);
    FuzzGetMechId(provider);
    FuzzIsFirstConnect(provider);
    FuzzAutoCentering(provider);
    FuzzDfxConnectDelay(provider);
    FuzzGetStrackingTime(provider);
    FuzzGetDfxInfo(provider);
    FuzzIsNeedSendTrackingData(provider);
    return 0;
}
