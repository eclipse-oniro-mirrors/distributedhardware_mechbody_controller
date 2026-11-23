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

#include "mechbodycontrollerutils_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>

#include "mechbody_controller_utils.h"

namespace OHOS {
using namespace OHOS::MechBodyController;
void GetAnonymStrFuzzTest(FuzzedDataProvider &fdp)
{
    std::string value = fdp.ConsumeRandomLengthString(256);
    GetAnonymStr(value);
}

void GetAnonymInt32FuzzTest(FuzzedDataProvider &fdp)
{
    int32_t value = fdp.ConsumeIntegral<int32_t>();
    GetAnonymInt32(value);
}

void GetAnonymUint32FuzzTest(FuzzedDataProvider &fdp)
{
    uint32_t value = fdp.ConsumeIntegral<uint32_t>();
    GetAnonymUint32(value);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    uint8_t funcIndex = fdp.ConsumeIntegral<uint8_t>() % 3;
    switch (funcIndex) {
        case 0:
            OHOS::GetAnonymStrFuzzTest(fdp);
            break;
        case 1:
            OHOS::GetAnonymInt32FuzzTest(fdp);
            break;
        case 2:
            OHOS::GetAnonymUint32FuzzTest(fdp);
            break;
        default:
            break;
    }
    return 0;
}