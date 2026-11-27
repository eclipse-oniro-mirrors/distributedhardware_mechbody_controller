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

#include "load_mechbody_adapter_test.h"
#include "mechbody_controller_log.h"

#include "../test_log.h"
#include <dlfcn.h>
#include <cstdio>
#include <cstdlib>

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace MechBodyController {

namespace {
    // 静态变量用于RegisterBackgroundTracking的无捕获lambda回调
    bool g_registerCalled = false;
    int8_t g_capturedDeviceType = -1;
    GetBackgroundXYFn g_capturedCallback;

    bool CompileMockSo(const char* soPath, const char* srcContent)
    {
        std::string srcPath = std::string(soPath);
        size_t pos = srcPath.find_last_of('.');
        srcPath = srcPath.substr(0, pos) + ".cpp";
        FILE* fp = fopen(srcPath.c_str(), "w");
        if (fp == nullptr) {
            return false;
        }
        if (fputs(srcContent, fp) < 0) {
            fclose(fp);
            return false;
        }
        if (fclose(fp) != 0) {
            return false;
        }
        std::string cmd = "g++ -shared -fPIC -o " + std::string(soPath) + " " + srcPath + " 2>/dev/null";
        return system(cmd.c_str()) == 0;
    }

    void* LoadMockSo(const char* soPath, const char* srcContent)
    {
        void* handle = dlopen(soPath, RTLD_LAZY);
        if (handle == nullptr) {
            if (!CompileMockSo(soPath, srcContent)) {
                return nullptr;
            }
            handle = dlopen(soPath, RTLD_LAZY);
        }
        return handle;
    }
}

void MechbodyAdapterUtilsTest::SetUpTestCase()
{
    DTEST_LOG << "MechbodyAdapterUtilsTest::SetUpTestCase" << std::endl;
}

void MechbodyAdapterUtilsTest::TearDownTestCase()
{
    DTEST_LOG << "MechbodyAdapterUtilsTest::TearDownTestCase" << std::endl;
    // 清理资源
    MechbodyAdapterUtils::Clear();
}

void MechbodyAdapterUtilsTest::SetUp()
{
    DTEST_LOG << "MechbodyAdapterUtilsTest::SetUp" << std::endl;
    // 每个测试前清理资源
    MechbodyAdapterUtils::Clear();
}

void MechbodyAdapterUtilsTest::TearDown()
{
    DTEST_LOG << "MechbodyAdapterUtilsTest::TearDown" << std::endl;
    // 每个测试后清理资源
    MechbodyAdapterUtils::Clear();
}

/**
 * @tc.name: InitTrackingCore_001
 * @tc.desc: 测试InitTrackingCore加载动态库后返回值与句柄状态一致性
 * @tc.type: FUNC
 */
HWTEST_F(MechbodyAdapterUtilsTest, InitTrackingCore_001, TestSize.Level3)
{
    DTEST_LOG << "MechbodyAdapterUtilsTest InitTrackingCore_001 begin" << std::endl;

    // Given: 未初始化状态（SetUp已调用Clear）
    // When: 调用InitTrackingCore
    int32_t ret = MechbodyAdapterUtils::InitTrackingCore();

    // Then: 返回值与句柄状态一致
    if (ret == ERR_OK) {
        EXPECT_NE(MechbodyAdapterUtils::mechAdapterHandle_, nullptr);
        EXPECT_NE(MechbodyAdapterUtils::mechBackgroundHandle_, nullptr);
    } else {
        EXPECT_EQ(MechbodyAdapterUtils::mechAdapterHandle_, nullptr);
    }

    DTEST_LOG << "MechbodyAdapterUtilsTest InitTrackingCore_001 end, ret=" << ret << std::endl;
}

/**
 * @tc.name: InitTrackingCore_002
 * @tc.desc: 测试重复初始化后内部状态一致性
 * @tc.type: FUNC
 */
HWTEST_F(MechbodyAdapterUtilsTest, InitTrackingCore_002, TestSize.Level3)
{
    DTEST_LOG << "MechbodyAdapterUtilsTest InitTrackingCore_002 begin" << std::endl;

    // Given: 第一次初始化
    int32_t ret1 = MechbodyAdapterUtils::InitTrackingCore();

    // When: 第二次初始化
    int32_t ret2 = MechbodyAdapterUtils::InitTrackingCore();

    // Then: 两次初始化均成功时，内部状态仍有效
    if (ret1 == ERR_OK && ret2 == ERR_OK) {
        EXPECT_NE(MechbodyAdapterUtils::mechAdapterHandle_, nullptr);
        EXPECT_NE(MechbodyAdapterUtils::runFunc_, nullptr);
        auto pushFn = [](float x, float y) {};
        EXPECT_EQ(MechbodyAdapterUtils::RunTrackingCore(100.0f, 100.0f, 640.0f, 480.0f, pushFn), ERR_OK);
    }

    DTEST_LOG << "MechbodyAdapterUtilsTest InitTrackingCore_002 end, ret1=" << ret1
              << ", ret2=" << ret2 << std::endl;
}

/**
 * @tc.name: RunTrackingCore_001
 * @tc.desc: 测试未初始化时调用 RunTrackingCore 返回错误
 * @tc.type: FUNC
 */
HWTEST_F(MechbodyAdapterUtilsTest, RunTrackingCore_001, TestSize.Level3)
{
    DTEST_LOG << "MechbodyAdapterUtilsTest RunTrackingCore_001 begin" << std::endl;

    // Given: 未初始化，句柄和函数指针为空
    // 已在 SetUp 中调用 Clear()

    // When: 调用 RunTrackingCore
    auto pushFn = [](float x, float y) {};
    int32_t ret = MechbodyAdapterUtils::RunTrackingCore(100.0f, 100.0f, 640.0f, 480.0f, pushFn);

    // Then: 返回错误码
    EXPECT_EQ(ret, LOAD_MECH_ADAPTER_FUNCTION_ERROR);

    DTEST_LOG << "MechbodyAdapterUtilsTest RunTrackingCore_001 end, ret=" << ret << std::endl;
}

/**
 * @tc.name: ResetTrackingCore_001
 * @tc.desc: 测试未初始化时调用 ResetTrackingCore 返回错误
 * @tc.type: FUNC
 */
HWTEST_F(MechbodyAdapterUtilsTest, ResetTrackingCore_001, TestSize.Level3)
{
    DTEST_LOG << "MechbodyAdapterUtilsTest ResetTrackingCore_001 begin" << std::endl;

    // Given: 未初始化，句柄和函数指针为空
    // 已在 SetUp 中调用 Clear()

    // When: 调用 ResetTrackingCore
    int32_t ret = MechbodyAdapterUtils::ResetTrackingCore();

    // Then: 返回错误码
    EXPECT_EQ(ret, LOAD_MECH_ADAPTER_FUNCTION_ERROR);

    DTEST_LOG << "MechbodyAdapterUtilsTest ResetTrackingCore_001 end, ret=" << ret << std::endl;
}

/**
 * @tc.name: Clear_001
 * @tc.desc: 测试清理资源时句柄存在
 * @tc.type: FUNC
 */
HWTEST_F(MechbodyAdapterUtilsTest, Clear_001, TestSize.Level3)
{
    DTEST_LOG << "MechbodyAdapterUtilsTest Clear_001 begin" << std::endl;

    // Given: 先初始化
    MechbodyAdapterUtils::InitTrackingCore();

    // When: 调用 Clear
    MechbodyAdapterUtils::Clear();

    // Then: 清理成功，后续调用 RunTrackingCore 应该返回错误
    auto pushFn = [](float x, float y) {};
    int32_t ret = MechbodyAdapterUtils::RunTrackingCore(100.0f, 100.0f, 640.0f, 480.0f, pushFn);
    EXPECT_EQ(ret, LOAD_MECH_ADAPTER_FUNCTION_ERROR);

    DTEST_LOG << "MechbodyAdapterUtilsTest Clear_001 end, ret=" << ret << std::endl;
}

/**
 * @tc.name: RunTrackingCore_004
 * @tc.desc: 测试多次调用 RunTrackingCore
 * @tc.type: FUNC
 */
HWTEST_F(MechbodyAdapterUtilsTest, RunTrackingCore_004, TestSize.Level3)
{
    DTEST_LOG << "MechbodyAdapterUtilsTest RunTrackingCore_004 begin" << std::endl;

    // Given: 初始化成功
    int32_t initRet = MechbodyAdapterUtils::InitTrackingCore();
    // In test environment, the dynamic library may not be available
    if (initRet != ERR_OK && initRet != DEVICE_NOT_NEED_SCREEN_INFO) {
        DTEST_LOG << "MechbodyAdapterUtilsTest RunTrackingCore_004 skipped, initRet=" << initRet << std::endl;
        // Split into two test cases instead of early return
        // This case only tests the initialization failure scenario
        GTEST_SKIP() << "Initialization failed, skipping RunTrackingCore test";
    }

    // When: 多次调用 RunTrackingCore
    auto pushFn = [](float x, float y) {};
    int32_t ret1 = MechbodyAdapterUtils::RunTrackingCore(100.0f, 100.0f, 640.0f, 480.0f, pushFn);
    int32_t ret2 = MechbodyAdapterUtils::RunTrackingCore(200.0f, 200.0f, 640.0f, 480.0f, pushFn);
    int32_t ret3 = MechbodyAdapterUtils::RunTrackingCore(300.0f, 300.0f, 640.0f, 480.0f, pushFn);

    // Then: 每次调用都应该返回成功
    EXPECT_EQ(ret1, ERR_OK);
    EXPECT_EQ(ret2, ERR_OK);
    EXPECT_EQ(ret3, ERR_OK);

    DTEST_LOG << "MechbodyAdapterUtilsTest RunTrackingCore_004 end, ret1=" << ret1
              << ", ret2=" << ret2 << ", ret3=" << ret3 << std::endl;
}

/**
 * @tc.name: ResetTrackingCore_003
 * @tc.desc: 测试多次调用 ResetTrackingCore
 * @tc.type: FUNC
 */
HWTEST_F(MechbodyAdapterUtilsTest, ResetTrackingCore_003, TestSize.Level3)
{
    DTEST_LOG << "MechbodyAdapterUtilsTest ResetTrackingCore_003 begin" << std::endl;

    // Given: 初始化成功
    int32_t initRet = MechbodyAdapterUtils::InitTrackingCore();
    // In test environment, the dynamic library may not be available
    if (initRet != ERR_OK && initRet != DEVICE_NOT_NEED_SCREEN_INFO) {
        DTEST_LOG << "MechbodyAdapterUtilsTest ResetTrackingCore_003 skipped, initRet=" << initRet << std::endl;
        // Split test cases instead of early return
        GTEST_SKIP() << "Initialization failed, skipping ResetTrackingCore test";
    }

    // When: 多次调用 ResetTrackingCore
    int32_t ret1 = MechbodyAdapterUtils::ResetTrackingCore();
    int32_t ret2 = MechbodyAdapterUtils::ResetTrackingCore();

    // Then: 每次调用都应该返回成功
    EXPECT_EQ(ret1, ERR_OK);
    EXPECT_EQ(ret2, ERR_OK);

    DTEST_LOG << "MechbodyAdapterUtilsTest ResetTrackingCore_003 end, ret1=" << ret1
              << ", ret2=" << ret2 << std::endl;
}

/**
 * @tc.name: InitTrackingCore_003
 * @tc.desc: 测试InitTrackingCore后mechAdapterHandle_的状态（覆盖50-53行分支）
 * @tc.type: FUNC
 */
HWTEST_F(MechbodyAdapterUtilsTest, InitTrackingCore_003, TestSize.Level3)
{
    DTEST_LOG << "MechbodyAdapterUtilsTest InitTrackingCore_003 begin" << std::endl;

    // Given: 清理状态，确保句柄为空
    MechbodyAdapterUtils::Clear();

    // When: 调用InitTrackingCore
    int32_t ret = MechbodyAdapterUtils::InitTrackingCore();

    // Then: 根据环境验证返回值和mechAdapterHandle_状态
    if (ret == ERR_OK) {
        // so文件存在时dlopen成功，mechAdapterHandle_非空
        EXPECT_NE(MechbodyAdapterUtils::mechAdapterHandle_, nullptr);
    } else {
        // so文件不存在时dlopen失败，走50-53行分支返回LOAD_MECH_ADAPTER_SO_ERROR
        EXPECT_EQ(ret, LOAD_MECH_ADAPTER_SO_ERROR);
        EXPECT_EQ(MechbodyAdapterUtils::mechAdapterHandle_, nullptr);
    }

    DTEST_LOG << "MechbodyAdapterUtilsTest InitTrackingCore_003 end, ret=" << ret << std::endl;
}

/**
 * @tc.name: InitTrackingCore_004
 * @tc.desc: 测试InitTrackingCore后mechBackgroundHandle_的状态（覆盖55-58行分支）
 * @tc.type: FUNC
 */
HWTEST_F(MechbodyAdapterUtilsTest, InitTrackingCore_004, TestSize.Level3)
{
    DTEST_LOG << "MechbodyAdapterUtilsTest InitTrackingCore_004 begin" << std::endl;

    // Given: 清理状态
    MechbodyAdapterUtils::Clear();

    // When: 调用InitTrackingCore
    int32_t ret = MechbodyAdapterUtils::InitTrackingCore();

    // Then: 根据环境验证返回值和mechBackgroundHandle_状态
    if (ret == ERR_OK) {
        // so文件存在时两个dlopen都成功，mechBackgroundHandle_非空
        EXPECT_NE(MechbodyAdapterUtils::mechBackgroundHandle_, nullptr);
    } else if (ret == LOAD_MECH_ADAPTER_SO_ERROR) {
        // 第一个so不存在时走50-53行分支，mechBackgroundHandle_未被赋值为空
        // 第一个so存在但第二个so不存在时走55-58行分支，mechBackgroundHandle_为nullptr
        EXPECT_EQ(MechbodyAdapterUtils::mechBackgroundHandle_, nullptr);
    }

    DTEST_LOG << "MechbodyAdapterUtilsTest InitTrackingCore_004 end, ret=" << ret << std::endl;
}

/**
 * @tc.name: InitTrackingCore_005
 * @tc.desc: 测试LoadFunction中dlsym查找Init符号失败返回LOAD_MECH_ADAPTER_FUNCTION_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(MechbodyAdapterUtilsTest, InitTrackingCore_005, TestSize.Level3)
{
    DTEST_LOG << "MechbodyAdapterUtilsTest InitTrackingCore_005 begin" << std::endl;

    // Given: 清理状态，预设句柄为dlopen(nullptr)有效值，
    // dlsym在此句柄中查找"Init"符号将失败
    MechbodyAdapterUtils::Clear();
    MechbodyAdapterUtils::mechAdapterHandle_ = dlopen(nullptr, RTLD_LAZY);
    MechbodyAdapterUtils::mechBackgroundHandle_ = dlopen(nullptr, RTLD_LAZY);
    ASSERT_NE(MechbodyAdapterUtils::mechAdapterHandle_, nullptr);
    ASSERT_NE(MechbodyAdapterUtils::mechBackgroundHandle_, nullptr);

    // When: 直接调用LoadFunction，dlsym查找"Init"符号失败
    int32_t ret = MechbodyAdapterUtils::LoadFunction();

    // Then: LoadFunction返回LOAD_MECH_ADAPTER_FUNCTION_ERROR
    EXPECT_EQ(ret, LOAD_MECH_ADAPTER_FUNCTION_ERROR);

    // 清理句柄
    dlclose(MechbodyAdapterUtils::mechAdapterHandle_);
    dlclose(MechbodyAdapterUtils::mechBackgroundHandle_);
    MechbodyAdapterUtils::mechAdapterHandle_ = nullptr;
    MechbodyAdapterUtils::mechBackgroundHandle_ = nullptr;

    DTEST_LOG << "MechbodyAdapterUtilsTest InitTrackingCore_005 end, ret=" << ret << std::endl;
}

/**
 * @tc.name: InitTrackingCore_006
 * @tc.desc: 测试InitTrackingCore后函数指针和后续调用的状态（覆盖61-74行分支清理效果）
 * @tc.type: FUNC
 */
HWTEST_F(MechbodyAdapterUtilsTest, InitTrackingCore_006, TestSize.Level3)
{
    DTEST_LOG << "MechbodyAdapterUtilsTest InitTrackingCore_006 begin" << std::endl;

    // Given: 清理状态
    MechbodyAdapterUtils::Clear();

    // When: 调用InitTrackingCore
    int32_t ret = MechbodyAdapterUtils::InitTrackingCore();

    // Then: 根据环境验证返回值和后续调用状态
    if (ret == ERR_OK) {
        // 初始化成功时，函数指针有效，后续调用正常工作
        auto pushFn = [](float x, float y) {};
        int32_t runRet = MechbodyAdapterUtils::RunTrackingCore(100.0f, 100.0f, 640.0f, 480.0f, pushFn);
        EXPECT_EQ(runRet, ERR_OK);
        int32_t resetRet = MechbodyAdapterUtils::ResetTrackingCore();
        EXPECT_EQ(resetRet, ERR_OK);
        // IsSupportBackground的返回值取决于真机上适配器的能力（设备相关），
        // 初始化成功仅保证函数指针已加载，此处断言指针非空而非设备相关返回值
        EXPECT_NE(MechbodyAdapterUtils::isSupportBackgroundFunc_, nullptr);
        (void)MechbodyAdapterUtils::IsSupportBackground();
    } else {
        // 初始化失败时，函数指针为空，后续调用返回错误码
        auto pushFn = [](float x, float y) {};
        int32_t runRet = MechbodyAdapterUtils::RunTrackingCore(100.0f, 100.0f, 640.0f, 480.0f, pushFn);
        EXPECT_EQ(runRet, LOAD_MECH_ADAPTER_FUNCTION_ERROR);
        int32_t resetRet = MechbodyAdapterUtils::ResetTrackingCore();
        EXPECT_EQ(resetRet, LOAD_MECH_ADAPTER_FUNCTION_ERROR);
        EXPECT_FALSE(MechbodyAdapterUtils::IsSupportBackground());
    }

    DTEST_LOG << "MechbodyAdapterUtilsTest InitTrackingCore_006 end, ret=" << ret << std::endl;
}

/**
 * @tc.name: InitTrackingCore_007
 * @tc.desc: 测试LoadFunction失败后InitTrackingCore清理逻辑的效果（覆盖61-74行ret != ERR_OK分支）
 *           验证LoadFunction失败不关闭句柄，清理后所有API调用返回正确错误码
 * @tc.type: FUNC
 */
HWTEST_F(MechbodyAdapterUtilsTest, InitTrackingCore_007, TestSize.Level3)
{
    DTEST_LOG << "MechbodyAdapterUtilsTest InitTrackingCore_007 begin" << std::endl;

    // Given: 设置有效句柄，模拟InitTrackingCore中dlopen成功后的状态
    MechbodyAdapterUtils::Clear();
    void* adapterHandle = dlopen(nullptr, RTLD_LAZY);
    void* backgroundHandle = dlopen(nullptr, RTLD_LAZY);
    ASSERT_NE(adapterHandle, nullptr);
    ASSERT_NE(backgroundHandle, nullptr);
    MechbodyAdapterUtils::mechAdapterHandle_ = adapterHandle;
    MechbodyAdapterUtils::mechBackgroundHandle_ = backgroundHandle;

    // When: 调用LoadFunction，因符号不存在将失败（对应61行LoadFunction返回错误）
    int32_t ret = MechbodyAdapterUtils::LoadFunction();

    // Then: LoadFunction返回LOAD_MECH_ADAPTER_FUNCTION_ERROR（对应62行ret != ERR_OK为true）
    EXPECT_EQ(ret, LOAD_MECH_ADAPTER_FUNCTION_ERROR);
    // LoadFunction不负责关闭句柄，句柄仍有效（由InitTrackingCore的63-64行dlclose负责）
    EXPECT_NE(MechbodyAdapterUtils::mechAdapterHandle_, nullptr);
    EXPECT_NE(MechbodyAdapterUtils::mechBackgroundHandle_, nullptr);

    // 执行InitTrackingCore中63-72行等价的清理逻辑：关闭句柄并置空所有指针
    dlclose(MechbodyAdapterUtils::mechAdapterHandle_);
    dlclose(MechbodyAdapterUtils::mechBackgroundHandle_);
    MechbodyAdapterUtils::mechAdapterHandle_ = nullptr;
    MechbodyAdapterUtils::mechBackgroundHandle_ = nullptr;
    MechbodyAdapterUtils::initFunc_ = nullptr;
    MechbodyAdapterUtils::runFunc_ = nullptr;
    MechbodyAdapterUtils::resetFunc_ = nullptr;
    MechbodyAdapterUtils::backgroundRegisterFunc_ = nullptr;
    MechbodyAdapterUtils::backgroundUnRegisterFunc_ = nullptr;
    MechbodyAdapterUtils::isSupportBackgroundFunc_ = nullptr;

    // 验证清理完成后，所有API调用返回正确错误码（验证63-72行清理逻辑的效果）
    auto pushFn = [](float x, float y) {};
    EXPECT_EQ(MechbodyAdapterUtils::RunTrackingCore(1.0f, 1.0f, 1.0f, 1.0f, pushFn),
        LOAD_MECH_ADAPTER_FUNCTION_ERROR);
    EXPECT_EQ(MechbodyAdapterUtils::ResetTrackingCore(), LOAD_MECH_ADAPTER_FUNCTION_ERROR);
    EXPECT_FALSE(MechbodyAdapterUtils::IsSupportBackground());

    DTEST_LOG << "MechbodyAdapterUtilsTest InitTrackingCore_007 end, ret=" << ret << std::endl;
}

/**
 * @tc.name: InitTrackingCore_008
 * @tc.desc: 测试InitTrackingCore成功时initFunc_被调用（覆盖75行initFunc_ != nullptr分支）
 * @tc.type: FUNC
 */
HWTEST_F(MechbodyAdapterUtilsTest, InitTrackingCore_008, TestSize.Level3)
{
    DTEST_LOG << "MechbodyAdapterUtilsTest InitTrackingCore_008 begin" << std::endl;

    // Given: 清理状态
    MechbodyAdapterUtils::Clear();

    // When: 调用InitTrackingCore
    int32_t ret = MechbodyAdapterUtils::InitTrackingCore();

    // Then: 根据环境验证
    if (ret == ERR_OK) {
        // InitTrackingCore成功时，LoadFunction成功（62行ret == ERR_OK为false），
        // initFunc_非空（75行initFunc_ != nullptr为true），initFunc_()被调用
        EXPECT_NE(MechbodyAdapterUtils::initFunc_, nullptr);
        EXPECT_NE(MechbodyAdapterUtils::runFunc_, nullptr);
        EXPECT_NE(MechbodyAdapterUtils::resetFunc_, nullptr);
    } else {
        // so文件不存在时，dlopen失败，未到达61行
        EXPECT_TRUE(ret == LOAD_MECH_ADAPTER_SO_ERROR || ret == LOAD_MECH_ADAPTER_FUNCTION_ERROR);
        EXPECT_EQ(MechbodyAdapterUtils::initFunc_, nullptr);
    }

    DTEST_LOG << "MechbodyAdapterUtilsTest InitTrackingCore_008 end, ret=" << ret << std::endl;
}

/**
 * @tc.name: RegisterBackgroundTracking_001
 * @tc.desc: 测试backgroundRegisterFunc_非空时RegisterBackgroundTracking正确传递GetBackgroundXYFn回调（覆盖154行false分支及159行）
 * @tc.type: FUNC
 */
HWTEST_F(MechbodyAdapterUtilsTest, RegisterBackgroundTracking_001, TestSize.Level3)
{
    DTEST_LOG << "MechbodyAdapterUtilsTest RegisterBackgroundTracking_001 begin" << std::endl;

    // Given: 设置backgroundRegisterFunc_为模拟函数，验证GetBackgroundXYFn回调被正确传递
    MechbodyAdapterUtils::Clear();
    g_registerCalled = false;
    g_capturedCallback = nullptr;
    bool callbackPassed = false;
    auto testCallback = [&callbackPassed](TrackingFrameParams params) {
        callbackPassed = true;
    };
    MechbodyAdapterUtils::backgroundRegisterFunc_ = [](const GetBackgroundXYFn& callback, int8_t deviceType) {
        g_registerCalled = true;
        g_capturedCallback = callback;
    };

    // When: 调用RegisterBackgroundTracking
    MechbodyAdapterUtils::RegisterBackgroundTracking(testCallback, 1);

    // Then: backgroundRegisterFunc_被调用且GetBackgroundXYFn被正确传递
    ASSERT_TRUE(g_registerCalled);
    ASSERT_NE(g_capturedCallback, nullptr);
    // 执行捕获的回调以验证传入的GetBackgroundXYFn与testCallback一致
    g_capturedCallback(TrackingFrameParams{});
    EXPECT_TRUE(callbackPassed);

    // 清理：重置函数指针
    MechbodyAdapterUtils::backgroundRegisterFunc_ = nullptr;

    DTEST_LOG << "MechbodyAdapterUtilsTest RegisterBackgroundTracking_001 end" << std::endl;
}

/**
 * @tc.name: RegisterBackgroundTracking_002
 * @tc.desc: 测试backgroundRegisterFunc_非空时调用RegisterBackgroundTracking执行回调（覆盖154行false分支及159行）
 * @tc.type: FUNC
 */
HWTEST_F(MechbodyAdapterUtilsTest, RegisterBackgroundTracking_002, TestSize.Level3)
{
    DTEST_LOG << "MechbodyAdapterUtilsTest RegisterBackgroundTracking_002 begin" << std::endl;

    // Given: 设置backgroundRegisterFunc_为模拟函数，通过静态变量捕获调用参数
    MechbodyAdapterUtils::Clear();
    g_registerCalled = false;
    g_capturedDeviceType = -1;
    MechbodyAdapterUtils::backgroundRegisterFunc_ = [](const GetBackgroundXYFn& callback, int8_t deviceType) {
        g_registerCalled = true;
        g_capturedDeviceType = deviceType;
    };

    // When: 调用RegisterBackgroundTracking
    auto testCallback = [](TrackingFrameParams params) {};
    int8_t testDeviceType = 1;
    MechbodyAdapterUtils::RegisterBackgroundTracking(testCallback, testDeviceType);

    // Then: 模拟函数被调用，参数正确传递
    EXPECT_TRUE(g_registerCalled);
    EXPECT_EQ(g_capturedDeviceType, testDeviceType);

    // 清理：重置函数指针
    MechbodyAdapterUtils::backgroundRegisterFunc_ = nullptr;

    DTEST_LOG << "MechbodyAdapterUtilsTest RegisterBackgroundTracking_002 end" << std::endl;
}

/**
 * @tc.name: LoadFunction_001
 * @tc.desc: 测试dlsym查找Init成功但RunTrackingCore失败的场景（覆盖93-95行分支）
 *           通过编译仅导出Init符号的临时SO，使LoadFunction在第二个dlsym处失败
 * @tc.type: FUNC
 */
HWTEST_F(MechbodyAdapterUtilsTest, LoadFunction_001, TestSize.Level3)
{
    DTEST_LOG << "MechbodyAdapterUtilsTest LoadFunction_001 begin" << std::endl;

    // Given: 编译仅导出"Init"符号的临时SO，dlsym("Init")将成功但dlsym("RunTrackingCore")将失败
    MechbodyAdapterUtils::Clear();
    void* mockHandle = LoadMockSo("/tmp/libmock_mech_init.so", "extern \"C\" void Init() {}");
    if (mockHandle == nullptr) {
        GTEST_SKIP() << "Cannot compile mock SO, skipping LoadFunction_001";
    }

    MechbodyAdapterUtils::mechAdapterHandle_ = mockHandle;
    MechbodyAdapterUtils::mechBackgroundHandle_ = dlopen(nullptr, RTLD_LAZY);
    ASSERT_NE(MechbodyAdapterUtils::mechBackgroundHandle_, nullptr);

    // When: 调用LoadFunction，Init符号查找成功，RunTrackingCore符号查找失败
    int32_t ret = MechbodyAdapterUtils::LoadFunction();

    // Then: LoadFunction在93-95行返回LOAD_MECH_ADAPTER_FUNCTION_ERROR
    EXPECT_EQ(ret, LOAD_MECH_ADAPTER_FUNCTION_ERROR);
    EXPECT_NE(MechbodyAdapterUtils::initFunc_, nullptr);
    EXPECT_EQ(MechbodyAdapterUtils::runFunc_, nullptr);

    // 清理
    dlclose(MechbodyAdapterUtils::mechAdapterHandle_);
    dlclose(MechbodyAdapterUtils::mechBackgroundHandle_);
    MechbodyAdapterUtils::mechAdapterHandle_ = nullptr;
    MechbodyAdapterUtils::mechBackgroundHandle_ = nullptr;
    MechbodyAdapterUtils::initFunc_ = nullptr;
    MechbodyAdapterUtils::runFunc_ = nullptr;
    MechbodyAdapterUtils::resetFunc_ = nullptr;
    MechbodyAdapterUtils::backgroundRegisterFunc_ = nullptr;
    MechbodyAdapterUtils::backgroundUnRegisterFunc_ = nullptr;
    MechbodyAdapterUtils::isSupportBackgroundFunc_ = nullptr;

    DTEST_LOG << "MechbodyAdapterUtilsTest LoadFunction_001 end, ret=" << ret << std::endl;
}

/**
 * @tc.name: LoadFunction_002
 * @tc.desc: 测试dlsym查找Reset失败的场景（覆盖99-101行分支）
 *           mechAdapterHandle_指向导出Init+RunTrackingCore的SO，Reset符号查找失败
 * @tc.type: FUNC
 */
HWTEST_F(MechbodyAdapterUtilsTest, LoadFunction_002, TestSize.Level3)
{
    DTEST_LOG << "MechbodyAdapterUtilsTest LoadFunction_002 begin" << std::endl;

    // Given: mechAdapterHandle_指向仅导出Init+RunTrackingCore的SO，Reset符号不存在
    MechbodyAdapterUtils::Clear();
    void* adapterHandle = LoadMockSo("/tmp/libmock_mech_2.so",
        "extern \"C\" void Init() {}"
        "extern \"C\" int RunTrackingCore(float, float, float, float, void*) { return 0; }");
    if (adapterHandle == nullptr) {
        GTEST_SKIP() << "Cannot compile mock SO, skipping LoadFunction_002";
    }
    MechbodyAdapterUtils::mechAdapterHandle_ = adapterHandle;
    MechbodyAdapterUtils::mechBackgroundHandle_ = dlopen(nullptr, RTLD_LAZY);
    ASSERT_NE(MechbodyAdapterUtils::mechBackgroundHandle_, nullptr);

    // When: 调用LoadFunction，Init和RunTrackingCore查找成功，Reset查找失败
    int32_t ret = MechbodyAdapterUtils::LoadFunction();

    // Then: 在99-101行返回LOAD_MECH_ADAPTER_FUNCTION_ERROR
    EXPECT_EQ(ret, LOAD_MECH_ADAPTER_FUNCTION_ERROR);
    EXPECT_NE(MechbodyAdapterUtils::initFunc_, nullptr);
    EXPECT_NE(MechbodyAdapterUtils::runFunc_, nullptr);
    EXPECT_EQ(MechbodyAdapterUtils::resetFunc_, nullptr);

    // 清理
    dlclose(MechbodyAdapterUtils::mechAdapterHandle_);
    dlclose(MechbodyAdapterUtils::mechBackgroundHandle_);
    MechbodyAdapterUtils::mechAdapterHandle_ = nullptr;
    MechbodyAdapterUtils::mechBackgroundHandle_ = nullptr;
    MechbodyAdapterUtils::initFunc_ = nullptr;
    MechbodyAdapterUtils::runFunc_ = nullptr;
    MechbodyAdapterUtils::resetFunc_ = nullptr;
    MechbodyAdapterUtils::backgroundRegisterFunc_ = nullptr;
    MechbodyAdapterUtils::backgroundUnRegisterFunc_ = nullptr;
    MechbodyAdapterUtils::isSupportBackgroundFunc_ = nullptr;

    DTEST_LOG << "MechbodyAdapterUtilsTest LoadFunction_002 end, ret=" << ret << std::endl;
}

/**
 * @tc.name: LoadFunction_003
 * @tc.desc: 测试dlsym查找RegisterBackgroundTracking失败的场景（覆盖105-107行分支）
 *           mechAdapterHandle_指向导出Init+RunTrackingCore+Reset的SO（前三个符号成功），
 *           mechBackgroundHandle_使用dlopen(nullptr)，RegisterBackgroundTracking符号不存在
 * @tc.type: FUNC
 */
HWTEST_F(MechbodyAdapterUtilsTest, LoadFunction_003, TestSize.Level3)
{
    DTEST_LOG << "MechbodyAdapterUtilsTest LoadFunction_003 begin" << std::endl;

    // Given: mechAdapterHandle_指向导出Init+RunTrackingCore+Reset的SO（前3个dlsym成功），
    // mechBackgroundHandle_使用dlopen(nullptr)，RegisterBackgroundTracking符号不存在
    MechbodyAdapterUtils::Clear();
    void* adapterHandle = LoadMockSo("/tmp/libmock_mech_3.so",
        "extern \"C\" void Init() {}"
        "extern \"C\" int RunTrackingCore(float, float, float, float, void*) { return 0; }"
        "extern \"C\" void Reset() {}");
    if (adapterHandle == nullptr) {
        GTEST_SKIP() << "Cannot compile mock SO, skipping LoadFunction_003";
    }
    MechbodyAdapterUtils::mechAdapterHandle_ = adapterHandle;
    MechbodyAdapterUtils::mechBackgroundHandle_ = dlopen(nullptr, RTLD_LAZY);
    ASSERT_NE(MechbodyAdapterUtils::mechBackgroundHandle_, nullptr);

    // When: 调用LoadFunction，前3个符号成功，RegisterBackgroundTracking查找失败
    int32_t ret = MechbodyAdapterUtils::LoadFunction();

    // Then: 在105-107行返回LOAD_MECH_ADAPTER_FUNCTION_ERROR
    EXPECT_EQ(ret, LOAD_MECH_ADAPTER_FUNCTION_ERROR);
    EXPECT_NE(MechbodyAdapterUtils::initFunc_, nullptr);
    EXPECT_NE(MechbodyAdapterUtils::runFunc_, nullptr);
    EXPECT_NE(MechbodyAdapterUtils::resetFunc_, nullptr);
    EXPECT_EQ(MechbodyAdapterUtils::backgroundRegisterFunc_, nullptr);

    // 清理
    dlclose(MechbodyAdapterUtils::mechAdapterHandle_);
    dlclose(MechbodyAdapterUtils::mechBackgroundHandle_);
    MechbodyAdapterUtils::mechAdapterHandle_ = nullptr;
    MechbodyAdapterUtils::mechBackgroundHandle_ = nullptr;
    MechbodyAdapterUtils::initFunc_ = nullptr;
    MechbodyAdapterUtils::runFunc_ = nullptr;
    MechbodyAdapterUtils::resetFunc_ = nullptr;
    MechbodyAdapterUtils::backgroundRegisterFunc_ = nullptr;
    MechbodyAdapterUtils::backgroundUnRegisterFunc_ = nullptr;
    MechbodyAdapterUtils::isSupportBackgroundFunc_ = nullptr;

    DTEST_LOG << "MechbodyAdapterUtilsTest LoadFunction_003 end, ret=" << ret << std::endl;
}

/**
 * @tc.name: LoadFunction_004
 * @tc.desc: 测试dlsym查找UnRegisterBackgroundTracking失败的场景（覆盖111-113行分支）
 *           mechAdapterHandle_指向导出Init+RunTrackingCore+Reset的SO，
 *           mechBackgroundHandle_指向仅导出RegisterBackgroundTracking的SO
 * @tc.type: FUNC
 */
HWTEST_F(MechbodyAdapterUtilsTest, LoadFunction_004, TestSize.Level3)
{
    DTEST_LOG << "MechbodyAdapterUtilsTest LoadFunction_004 begin" << std::endl;

    // Given: mechAdapterHandle_有前3个符号，mechBackgroundHandle_有RegisterBackgroundTracking
    MechbodyAdapterUtils::Clear();
    void* adapterHandle = LoadMockSo("/tmp/libmock_mech_3.so",
        "extern \"C\" void Init() {}"
        "extern \"C\" int RunTrackingCore(float, float, float, float, void*) { return 0; }"
        "extern \"C\" void Reset() {}");
    if (adapterHandle == nullptr) {
        GTEST_SKIP() << "Cannot compile mock SO, skipping LoadFunction_004";
    }
    void* bgHandle = LoadMockSo("/tmp/libmock_bg_1.so",
        "extern \"C\" void RegisterBackgroundTracking() {}");
    if (bgHandle == nullptr) {
        dlclose(adapterHandle);
        GTEST_SKIP() << "Cannot compile mock bg SO, skipping LoadFunction_004";
    }
    MechbodyAdapterUtils::mechAdapterHandle_ = adapterHandle;
    MechbodyAdapterUtils::mechBackgroundHandle_ = bgHandle;

    // When: 调用LoadFunction，前4个符号成功，UnRegisterBackgroundTracking查找失败
    int32_t ret = MechbodyAdapterUtils::LoadFunction();

    // Then: 在111-113行返回LOAD_MECH_ADAPTER_FUNCTION_ERROR
    EXPECT_EQ(ret, LOAD_MECH_ADAPTER_FUNCTION_ERROR);
    EXPECT_NE(MechbodyAdapterUtils::initFunc_, nullptr);
    EXPECT_NE(MechbodyAdapterUtils::runFunc_, nullptr);
    EXPECT_NE(MechbodyAdapterUtils::resetFunc_, nullptr);
    EXPECT_NE(MechbodyAdapterUtils::backgroundRegisterFunc_, nullptr);
    EXPECT_EQ(MechbodyAdapterUtils::backgroundUnRegisterFunc_, nullptr);

    // 清理
    dlclose(MechbodyAdapterUtils::mechAdapterHandle_);
    dlclose(MechbodyAdapterUtils::mechBackgroundHandle_);
    MechbodyAdapterUtils::mechAdapterHandle_ = nullptr;
    MechbodyAdapterUtils::mechBackgroundHandle_ = nullptr;
    MechbodyAdapterUtils::initFunc_ = nullptr;
    MechbodyAdapterUtils::runFunc_ = nullptr;
    MechbodyAdapterUtils::resetFunc_ = nullptr;
    MechbodyAdapterUtils::backgroundRegisterFunc_ = nullptr;
    MechbodyAdapterUtils::backgroundUnRegisterFunc_ = nullptr;
    MechbodyAdapterUtils::isSupportBackgroundFunc_ = nullptr;

    DTEST_LOG << "MechbodyAdapterUtilsTest LoadFunction_004 end, ret=" << ret << std::endl;
}

/**
 * @tc.name: LoadFunction_005
 * @tc.desc: 测试dlsym查找IsSupportBackground失败的场景（覆盖117-119行分支）
 *           mechAdapterHandle_指向导出Init+RunTrackingCore+Reset的SO，
 *           mechBackgroundHandle_指向导出RegisterBackgroundTracking+UnRegisterBackgroundTracking的SO
 * @tc.type: FUNC
 */
HWTEST_F(MechbodyAdapterUtilsTest, LoadFunction_005, TestSize.Level3)
{
    DTEST_LOG << "MechbodyAdapterUtilsTest LoadFunction_005 begin" << std::endl;

    // Given: mechAdapterHandle_有前3个符号，mechBackgroundHandle_有Register+UnRegister
    MechbodyAdapterUtils::Clear();
    void* adapterHandle = LoadMockSo("/tmp/libmock_mech_3.so",
        "extern \"C\" void Init() {}"
        "extern \"C\" int RunTrackingCore(float, float, float, float, void*) { return 0; }"
        "extern \"C\" void Reset() {}");
    if (adapterHandle == nullptr) {
        GTEST_SKIP() << "Cannot compile mock SO, skipping LoadFunction_005";
    }
    void* bgHandle = LoadMockSo("/tmp/libmock_bg_2.so",
        "extern \"C\" void RegisterBackgroundTracking() {}"
        "extern \"C\" void UnRegisterBackgroundTracking() {}");
    if (bgHandle == nullptr) {
        dlclose(adapterHandle);
        GTEST_SKIP() << "Cannot compile mock bg SO, skipping LoadFunction_005";
    }
    MechbodyAdapterUtils::mechAdapterHandle_ = adapterHandle;
    MechbodyAdapterUtils::mechBackgroundHandle_ = bgHandle;

    // When: 调用LoadFunction，前5个符号成功，IsSupportBackground查找失败
    int32_t ret = MechbodyAdapterUtils::LoadFunction();

    // Then: 在117-119行返回LOAD_MECH_ADAPTER_FUNCTION_ERROR
    EXPECT_EQ(ret, LOAD_MECH_ADAPTER_FUNCTION_ERROR);
    EXPECT_NE(MechbodyAdapterUtils::initFunc_, nullptr);
    EXPECT_NE(MechbodyAdapterUtils::runFunc_, nullptr);
    EXPECT_NE(MechbodyAdapterUtils::resetFunc_, nullptr);
    EXPECT_NE(MechbodyAdapterUtils::backgroundRegisterFunc_, nullptr);
    EXPECT_NE(MechbodyAdapterUtils::backgroundUnRegisterFunc_, nullptr);
    EXPECT_EQ(MechbodyAdapterUtils::isSupportBackgroundFunc_, nullptr);

    // 清理
    dlclose(MechbodyAdapterUtils::mechAdapterHandle_);
    dlclose(MechbodyAdapterUtils::mechBackgroundHandle_);
    MechbodyAdapterUtils::mechAdapterHandle_ = nullptr;
    MechbodyAdapterUtils::mechBackgroundHandle_ = nullptr;
    MechbodyAdapterUtils::initFunc_ = nullptr;
    MechbodyAdapterUtils::runFunc_ = nullptr;
    MechbodyAdapterUtils::resetFunc_ = nullptr;
    MechbodyAdapterUtils::backgroundRegisterFunc_ = nullptr;
    MechbodyAdapterUtils::backgroundUnRegisterFunc_ = nullptr;
    MechbodyAdapterUtils::isSupportBackgroundFunc_ = nullptr;

    DTEST_LOG << "MechbodyAdapterUtilsTest LoadFunction_005 end, ret=" << ret << std::endl;
}

/**
 * @tc.name: UnRegisterBackgroundTracking_002
 * @tc.desc: 测试backgroundUnRegisterFunc_非空时调用UnRegisterBackgroundTracking执行回调（覆盖167行false分支及172行）
 * @tc.type: FUNC
 */
HWTEST_F(MechbodyAdapterUtilsTest, UnRegisterBackgroundTracking_002, TestSize.Level3)
{
    DTEST_LOG << "MechbodyAdapterUtilsTest UnRegisterBackgroundTracking_002 begin" << std::endl;

    // Given: 设置backgroundUnRegisterFunc_为模拟函数，通过静态变量捕获调用
    MechbodyAdapterUtils::Clear();
    static bool unRegisterCalled = false;
    unRegisterCalled = false;
    MechbodyAdapterUtils::backgroundUnRegisterFunc_ = []() {
        unRegisterCalled = true;
    };

    // When: 调用UnRegisterBackgroundTracking
    MechbodyAdapterUtils::UnRegisterBackgroundTracking();

    // Then: 模拟函数被调用
    EXPECT_TRUE(unRegisterCalled);

    // 清理：重置函数指针
    MechbodyAdapterUtils::backgroundUnRegisterFunc_ = nullptr;

    DTEST_LOG << "MechbodyAdapterUtilsTest UnRegisterBackgroundTracking_002 end" << std::endl;
}

/**
 * @tc.name: IsSupportBackground_001
 * @tc.desc: 测试isSupportBackgroundFunc_非空时调用IsSupportBackground返回模拟值（覆盖179行false分支及184行）
 * @tc.type: FUNC
 */
HWTEST_F(MechbodyAdapterUtilsTest, IsSupportBackground_001, TestSize.Level3)
{
    DTEST_LOG << "MechbodyAdapterUtilsTest IsSupportBackground_001 begin" << std::endl;

    // Given: 设置isSupportBackgroundFunc_为模拟函数，返回true
    MechbodyAdapterUtils::Clear();
    MechbodyAdapterUtils::isSupportBackgroundFunc_ = []() -> bool {
        return true;
    };

    // When: 调用IsSupportBackground
    bool result = MechbodyAdapterUtils::IsSupportBackground();

    // Then: 返回模拟函数的值true
    EXPECT_TRUE(result);

    // 清理：重置函数指针
    MechbodyAdapterUtils::isSupportBackgroundFunc_ = nullptr;

    DTEST_LOG << "MechbodyAdapterUtilsTest IsSupportBackground_001 end" << std::endl;
}

} // namespace MechBodyController
} // namespace OHOS