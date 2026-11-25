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
using FuzzFunc = void (*)(FuzzedDataProvider &);
const FuzzFunc FUZZ_FUNCS[] = {
    OHOS::GetAnonymStrFuzzTest,
    OHOS::GetAnonymInt32FuzzTest,
    OHOS::GetAnonymUint32FuzzTest,
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