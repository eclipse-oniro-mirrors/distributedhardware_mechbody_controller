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
#include "hisyseventutils_fuzzer.h"
#include <string>
#include <vector>

using namespace OHOS::MechBodyController;
namespace {
constexpr int32_t MIN_MECH_TYPE = static_cast<int32_t>(MechType::UNKNOWN);
constexpr int32_t MAX_MECH_TYPE = static_cast<int32_t>(MechType::WHEEL_BASE);
constexpr int32_t MIN_START_RESULT_CODE = 0;
constexpr int32_t MAX_START_RESULT_CODE = 2;
} // namespace


namespace {
void FuzzDotReportFocustrackingStartEvent(FuzzedDataProvider &fdp)
{
    std::string appName = fdp.ConsumeRandomLengthString();
    HisyseventUtils::DotReportFocustrackingStartEvent(appName);
}

void FuzzDotReportMechKitStartEvent(FuzzedDataProvider &fdp)
{
    MechKitStartReportInfo reportInfo;
    int32_t connectTypeValue = fdp.ConsumeIntegralInRange<int32_t>(-1, 1);
    reportInfo.connectType = static_cast<ConnectType>(connectTypeValue);
    int32_t deviceTypeValue = fdp.ConsumeIntegralInRange<int32_t>(MIN_MECH_TYPE, MAX_MECH_TYPE);
    reportInfo.deviceType = static_cast<MechType>(deviceTypeValue);
    int32_t resultCodeValue = fdp.ConsumeIntegralInRange<int32_t>(MIN_START_RESULT_CODE, MAX_START_RESULT_CODE);
    reportInfo.mechkitStartResultCode = static_cast<MechKitStartResCode>(resultCodeValue);
    reportInfo.deviceName = fdp.ConsumeRandomLengthString();
    reportInfo.deviceModel = fdp.ConsumeRandomLengthString();
    HisyseventUtils::DotReportMechKitStartEvent(reportInfo);
}

void FuzzDoReportMechkitControlStatisticEvent(FuzzedDataProvider &fdp)
{
    MechkitControlInfo controlInfo;
    controlInfo.upWard = fdp.ConsumeIntegral<uint32_t>();
    controlInfo.downWard = fdp.ConsumeIntegral<uint32_t>();
    controlInfo.turnLeft = fdp.ConsumeIntegral<uint32_t>();
    controlInfo.turnRight = fdp.ConsumeIntegral<uint32_t>();
    controlInfo.fastRotation = fdp.ConsumeIntegral<uint32_t>();
    controlInfo.landScapePortrait = fdp.ConsumeIntegral<uint32_t>();
    controlInfo.cameraMode = fdp.ConsumeIntegral<uint8_t>();
    controlInfo.trackingDuration = fdp.ConsumeIntegral<uint64_t>();
    controlInfo.cameraType = fdp.ConsumeIntegral<uint8_t>();
    controlInfo.zoomRatio = fdp.ConsumeFloatingPoint<float>();
    controlInfo.packageName = fdp.ConsumeRandomLengthString();
    controlInfo.obstacleNumber = fdp.ConsumeIntegral<uint8_t>();
    controlInfo.cliffNumber = fdp.ConsumeIntegral<uint8_t>();
    controlInfo.successNumber = fdp.ConsumeIntegral<uint32_t>();
    controlInfo.failNumber = fdp.ConsumeIntegral<uint32_t>();
    controlInfo.deviceType = fdp.ConsumeIntegral<uint8_t>();
    controlInfo.stickNum = fdp.ConsumeIntegral<uint32_t>();

    uint8_t appNameCount = fdp.ConsumeIntegral<uint8_t>() % 8;
    for (uint8_t i = 0; i < appNameCount; i++) {
        controlInfo.appName.push_back(fdp.ConsumeRandomLengthString());
    }

    uint8_t existenceTimeCount = fdp.ConsumeIntegral<uint8_t>() % 8;
    for (uint8_t i = 0; i < existenceTimeCount; i++) {
        controlInfo.existenceTime.push_back(fdp.ConsumeIntegral<uint64_t>());
    }

    controlInfo.connectDelay = fdp.ConsumeIntegral<uint32_t>();
    controlInfo.connectCode = fdp.ConsumeIntegral<uint32_t>();

    uint8_t cmdWordCount = fdp.ConsumeIntegral<uint8_t>() % 8;
    for (uint8_t i = 0; i < cmdWordCount; i++) {
        controlInfo.cmdWord.push_back(fdp.ConsumeIntegral<uint16_t>());
    }

    uint8_t errorCodeCount = fdp.ConsumeIntegral<uint8_t>() % 8;
    for (uint8_t i = 0; i < errorCodeCount; i++) {
        controlInfo.errorCode.push_back(fdp.ConsumeIntegral<uint16_t>());
    }

    HisyseventUtils::DoReportMechkitControlStatisticEvent(controlInfo);
}
} // namespace

using FuzzFunc = void (*)(FuzzedDataProvider &);
const FuzzFunc FUZZ_FUNCS[] = {
    FuzzDotReportFocustrackingStartEvent,
    FuzzDotReportMechKitStartEvent,
    FuzzDoReportMechkitControlStatisticEvent,
};
constexpr size_t FUZZ_FUNC_COUNT = sizeof(FUZZ_FUNCS) / sizeof(FUZZ_FUNCS[0]);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    uint8_t funcIndex = fdp.ConsumeIntegral<uint8_t>() % FUZZ_FUNC_COUNT;
    if (funcIndex < FUZZ_FUNC_COUNT) {
        FUZZ_FUNCS[funcIndex](fdp);
    }
    return 0;
}