# 科大讯飞 MDM (com.iflytek.ebg.aistudy.mdm) 深度安全审计报告

> **分析对象：** 科大讯飞 AI 学习设备 MDM（移动设备管理）APK 反编译源码  
> **版本号：** 1.0.0.4120 (versionCode: 1004120)  
> **设备类型：** X2（学习机）  
> **编译SDK：** Android 13 (API 33)  
> **系统权限：** `android.uid.system`  
> **分析时间：** 2026-05-23

---

## 目录

1. [项目架构总览](#1-项目架构总览)
2. [入口层分析](#2-入口层分析)
3. [服务层分析](#3-服务层分析)
4. [控制执行层分析](#4-控制执行层分析)
5. [数据层分析](#5-数据层分析)
6. [后门/调试入口分析](#6-后门调试入口分析)
7. [广播接收器分析](#7-广播接收器分析)
8. [安全隐患汇总](#8-安全隐患汇总)
9. [修复建议](#9-修复建议)

---

## 1. 项目架构总览

### 1.1 模块架构图

```
┌─────────────────────────────────────────────────────────────┐
│                        入口层 (Entry Layer)                   │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │ BOOT_       │  │ 远程Push指令  │  │ exported组件       │  │
│  │ COMPLETED   │  │ (云端下发)   │  │ (外部可直接调用)   │  │
│  └──────┬──────┘  └──────┬───────┘  └────────┬───────────┘  │
│         │                │                    │              │
│  ┌──────▼────────────────▼────────────────────▼───────────┐  │
│  │              SystemActionReceiver.java                  │  │
│  │  监听开机广播 → 启动 MDMService → 进入管控循环         │  │
│  └──────────────────────┬─────────────────────────────────┘  │
└─────────────────────────┼─────────────────────────────────────┘
                          │
┌─────────────────────────▼─────────────────────────────────────┐
│                      服务层 (Service Layer)                     │
│  ┌────────────┐  ┌──────────────────┐  ┌──────────────────┐   │
│  │ MDMService │  │ DumpService      │  │ UniversalTransfer│   │
│  │ (管控入口)  │  │ (系统dump)       │  │ Service          │   │
│  └─────┬──────┘  └──────────────────┘  └────────┬─────────┘   │
│        │                                         │            │
│  ┌─────▼──────────────────────────────┐          │            │
│  │    RealDeviceControlManager /      │          │            │
│  │    X2DeviceControlManager          │          │            │
│  │    + X2AppControl / C1692a         │          │            │
│  │    设备/应用管控 核心管理器           │          │            │
│  └─────────────────┬──────────────────┘          │            │
└────────────────────┼─────────────────────────────┼────────────┘
                     │                             │
┌────────────────────▼─────────────────────────────▼────────────┐
│                   控制执行层 (Execution Layer)                  │
│  ┌─────────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ DeviceControl   │  │ NetVisit     │  │ AppControl       │  │
│  │ Executor.java   │  │ (VPN模式)    │  │ (应用时长/禁用)   │  │
│  │ - 锁屏/解锁     │  │              │  │                  │  │
│  │ - 音量控制      │  │              │  │                  │  │
│  │ - 进程查杀      │  │              │  │                  │  │
│  │ - Settings写入  │  │              │  │                  │  │
│  └────────┬────────┘  └──────┬───────┘  └────────┬─────────┘  │
│           │                  │                    │            │
│  ┌────────▼──────────────────▼────────────────────▼────────┐  │
│  │         LockWindow / LockUtil / C1878f                  │  │
│  │         - 悬浮窗锁屏界面                                │  │
│  │         - 系统锁屏 (DevicePolicyManager)                │  │
│  │         - 单次/全天时长倒计时                            │  │
│  └────────────────────────┬────────────────────────────────┘  │
└───────────────────────────┼─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                      数据层 (Data Layer)                         │
│  ┌─────────────────┐  ┌──────────────────┐  ┌───────────────┐  │
│  │ ControlData     │  │ StatisticalData  │  │ CommonData    │  │
│  │ ContentProvider │  │ ContentProvider  │  │ ContentProvider│  │
│  │ (应用控制数据)   │  │ (使用统计)       │  │ (公共数据)     │  │
│  └─────────────────┘  └──────────────────┘  └───────────────┘  │
│  ┌─────────────────┐  ┌──────────────────┐                      │
│  │ BusinessControl │  │ LocalDataCenter  │                      │
│  │ ContentProvider │  │ ContentProvider  │                      │
│  │ (业务管控)       │  │ (本地数据中心)    │                      │
│  └─────────────────┘  └──────────────────┘                      │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    后门层 (Backdoor Layer)                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │Account   │ │NetVisit  │ │AppUseTime│ │DeviceState│           │
│  │Backdoor  │ │Backdoor  │ │Backdoor  │ │Backdoor  │           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │ScreenShot│ │Headset   │ │TimeCalc  │ │UnlockTimes│           │
│  │Backdoor  │ │Backdoor  │ │Backdoor  │ │Backdoor  │           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 核心控制链路

```
远程Push服务器
    │
    ▼ 推送指令: duration_control / time_control / device_eye_shield / ...
ControlInstructionHandler.java (解析指令)
    │
    ├── appControl() → 应用管控指令
    │   ├── businessControl() → 调用 C1754a.m3727k() 刷新设备管控
    │   └── C1692a.m3387j() → 调用 X2AppControl.mo3490a() 刷新应用管控
    │       ├── C0834a (AppControlInfoQuery) → 从 ContentProvider 读取管控配置
    │       ├── AppControlParserX2 → 解析配置为 AppControlResult
    │       └── C1720d (AppUseControl) → 执行应用管控(杀进程/限制启动)
    │
    └── initCreators() → 注册 20+ 指令处理器
        ├── DurationControlCreator / TimeControlCreator
        ├── DeviceDurationControlCreator / DeviceTimeControlCreator
        ├── DeviceEyeShieldCreator / DeviceScreenshotControlCreator
        ├── UrlBlackListControlCreator / RemoteScreenShotControlCreator
        └── ...
```

---

## 2. 入口层分析

### 2.1 MDMApplication.java

**文件路径：** `com/iflytek/ebg/aistudy/app/MDMApplication.java`

**职责：** 应用入口，初始化所有子模块。

**关键初始化流程：**

1. **SplashActivity 启动** — 通过 `Intent.FLAG_ACTIVITY_NEW_TASK` 拉起主界面
2. **模块初始化顺序：**
   - `C4829a.m16406a()` → 基础模块初始化
   - `MDMPushConfig.m7799a()` → Push SDK 配置注册（`AIStudyPushMessageReceiverImpl` + `ControlInstructionHandler`）
   - `C5247a.m18104a()` → 日志系统初始化
   - `C1947a.m4480a()` → 网络访问控制初始化
   - `EDUDataControlComponentImpl.init()` → 教育数据控制组件
   - `EDUStatisticsComponentImpl.init()` → 教育统计组件
3. **定时轮询：** `C1947a.m4482c()` 定期拉取最新管控配置

### 2.2 SystemActionReceiver.java

**文件路径：** `com/iflytek/ebg/aistudy/mdm/service/SystemActionReceiver.java`

**职责：** 监听系统广播（BOOT_COMPLETED、用户切换等），启动 MDM 管控服务。

**关键逻辑：**
```
BOOT_COMPLETED 广播
    │
    ▼
C1965b.m4584a(context)  ← 判断是否需要启动
    │ (检查条件：有用户登录 + 非首次启动)
    ▼
启动 MDMService
    │
    ▼
进入管控循环 (每5分钟轮询 / Push实时下发)
```

### 2.3 AIStudyPushMessageReceiverImpl.java

**文件路径：** `com/iflytek/ebg/aistudy/mdm/AIStudyPushMessageReceiverImpl.java`

**职责：** 接收来自科大讯飞 Push SDK 的远程指令。

**指令处理流程：**
```java
onReceive(instruction) {
    switch (instruction.getType()) {
        case "appControl":
            → ControlInstructionHandler.appControl(instruction.getContent())
            → businessControl() 刷新设备管控
            → C1692a.m3387j() 刷新应用管控

        case "deviceControl":
            → ControlInstructionHandler.initCreators() 注册的控制指令
            → 20+ 种管控指令类型
            → 每种指令对应一个 Creator/Handler
            → 触发对应模块的查询+执行
    }
}
```

**支持的远程指令类型（20+种）：**

| 指令类型 | 功能描述 | 对应模块 |
|----------|----------|----------|
| `duration_control` | 应用使用时长限制 | AppControl |
| `time_control` | 应用使用时间段限制 | AppControl |
| `game_control` | 游戏类应用管控 | AppControl |
| `device_duration_control` | 整机使用时长限制 | DeviceControl |
| `device_time_control` | 整机使用时间段限制 | DeviceControl |
| `device_temp_duration_control` | 整机临时时长 | DeviceControl |
| `app_control` | 通用应用管控 | AppControl |
| `single_app_time_control` | 单应用时长控制 | AppControl |
| `device_eye_shield` | 护眼模式控制 | EyeShield |
| `answer_control` | 答题类应用管控 | AppControl |
| `common_device_control` | 通用设备控制 | DeviceControl |
| `url_blacklist_control` | 网址黑名单控制 | NetVisit |
| `device_screenshot_control` | 截图管控 | ScreenshotControl |
| `device_screenRecord_control` | 录屏管控 | ScreenshotControl |
| `user_device_state_refresh` | 设备状态刷新 | DeviceState |
| `fast_reporting` | 快速上报 | Reporting |
| `remote_screen_shot_control` | 远程截图 | ScreenshotControl |
| `assign_allow_app` | 指定允许安装应用 | AppInstall |
| `mtu_config_control` | MTU配置控制 | NetworkConfig |

---

## 3. 服务层分析

### 3.1 MDMService.java

**文件路径：** `com/iflytek/ebg/aistudy/mdm/service/MDMService.java`

**类型：** 空壳 Service，仅负责启动入口。

**实际工作：** `onCreate()` 调用 `C1964a.m4580a(context)` 完成实际初始化，包括：
- 注册广播接收器
- 启动管控定时器
- 连接 Push SDK
- 初始化设备管理员

### 3.2 DumpService.java

**文件路径：** `com/iflytek/ebg/aistudy/mdm/service/DumpService.java`

**类型：** 系统 dump 服务。

**安全评估：** `exported="true"` 无权限保护，返回 `BinderC1961a` 实现 `InterfaceC5230a`，其 `dump()` 方法可 dump 系统敏感信息。

**暴露风险：** 任何应用可通过 `adb shell dumpsys` 或绑定该 Service 获取内部状态信息。

### 3.3 UniversalTransferService.java

**文件路径：** `com/iflytek/ebg/aistudy/mdm/service/UniversalTransferService.java`

**类型：** 跨应用数据传输服务，暴露 AIDL 接口。

**暴露的 AIDL 接口：**

| 接口名称 | 方法 | 功能 | 安全风险 |
|----------|------|------|----------|
| IAppDeviceIdService | getAppDeviceId(appPackageName) | 获取任意应用的设备ID | 隐私泄露 |
| IAiStudyTransformAidl | call(methodName, data) | 通用数据传输 | 可注入伪造数据 |

**`call()` 方法支持的 methodName：**
- `uploadlogs` — 向 MDM 注入日志数据
- `learninglogs` — 注入学习日志数据
- `addGestureControlInfo` — 添加手势控制信息
- `removeGestureControlInfo` — 删除手势控制信息

**安全风险：** 无任何认证机制，任何第三方应用绑定此服务后可调用 `call()` 方法注入任意数据。

---

## 4. 控制执行层分析

### 4.1 应用管控 (AppControl)

#### 4.1.1 C1692a.java — 应用管控入口

**文件路径：** `com/iflytek/ebg/aistudy/mdm/control/app/C1692a.java`

**职责：** 应用管控的核心管理类，协调应用控制和小程序控制。

**关键组件：**
```java
// 单例模式
public static final C1692a f2685a

// 核心组件
context          → Application 上下文
singleTaskRunner → "应用管控管理器" 单任务执行器
factory          → C1730b 控制结果工厂类
activityControl  → C1694a 活动控制（前台 Activity 管控）
appletControl    → C1721a 小程序控制
appList          → 受管控应用列表
```

**关键方法：**

| 方法 | 功能 |
|------|------|
| `m3383d()` | 重新执行管控 — 调用 factory 解析配置 → appletControl → activityControl |
| `m3384f()` | 获取当前应用管控解析结果 (AppControlResult) |
| `m3386h(isForce, needDelay)` | 强制刷新应用管控配置 |
| `m3387j(isForce, needDelay)` | 刷新应用管控（从 Push 指令触发） |
| `m3388l()` | 清理管控 — 清除 appletControl 和 activityControl |

**管控执行流程：**
```
C1692a.m3387j(true, false)
    │
    ├── factory.m3588c().mo3490a()  → 获取应用控制结果
    │   ├── C0834a (AppControlInfoQuery) → 从 ContentProvider 查询配置
    │   │   ContentResolver.query("content://...control/control_data/1/*")
    │   │
    │   ├── AppControlParserX2 → 解析 JSON 配置为控制策略
    │   │   输入: AppControlInfo + 用户使用时长 + 当前时间
    │   │   输出: AppControlResult
    │   │
    │   └── C1720d (AppUseControl) → 执行实际管控
    │       ├── 杀进程 (ProcessKill)
    │       ├── 限制启动 (ActivityControl)
    │       └── 弹窗提醒 (ControlReminder)
    │
    ├── appletControl.m3550c() → 小程序控制刷新
    └── activityControl.m3418c(appList) → 前台 Activity 管控
```

#### 4.1.2 X2AppControl.java — 应用控制实现

**文件路径：** `com/iflytek/ebg/aistudy/mdm/control/app/app_control/X2AppControl.java`

**职责：** 具体的应用控制策略执行。

**核心字段：**
```java
appContext         → Context
singleTaskRunner   → 异步任务执行器
now                → 获取当前时间戳
getUserAppsTime    → 获取用户各应用使用时长
appControlInfoQuery → C0834a 配置查询器
appUseControl      → C1720d 应用使用控制执行器
appControlParser   → AppControlParserX2 配置解析器
appControlParseResult → 解析结果缓存
appControlInfo     → 配置信息缓存（SharedPreferences持久化）
```

**持久化机制：**
- 配置存储在 SharedPreferences key: `key.app.control.configs`
- 每次更新配置后自动序列化保存
- 启动时自动反序列化恢复

**管控逻辑：**
```
mo3490a(isForce, needDelay, onSuccess)
    │
    ├── SingleTaskRunner 异步执行
    │   ├── C0834a.m607F() → 查询最新管控配置
    │   │   isForce=true: 强制从服务器拉取
    │   │   needDelay=true: 延迟查询
    │   │
    │   ├── m3489n(AppControlInfo) → 更新本地配置缓存
    │   │   └── SharedPreferences 持久化
    │   │
    │   └── onSuccess.invoke(appList) → 回调通知应用列表变更
    │
    └── mo3491b() → 立即执行管控
        ├── appControlParser.m5797j(appControlInfo, userAppsTime, currentTime)
        │   解析控制策略，返回 AppControlResult
        │
        └── appUseControl.m3542a(context, result, appControlInfo)
            执行管控动作
```

#### 4.1.3 C1718b.java — 应用使用控制

**文件路径：** `com/iflytek/ebg/aistudy/mdm/control/app/app_control/executor/C1718b.java`

**职责：** 实际执行应用管控动作（杀进程、限制启动等）。

**管控动作：**
1. **进程查杀** — 对超时应用调用 `C1842a.m4076f()` 杀进程
2. **Activity 限制** — 通过 `activityControl` 阻止受限应用前台启动
3. **弹窗提醒** — `ControlReminderParser` 在锁屏前显示倒计时提醒

### 4.2 设备管控 (DeviceControl)

#### 4.2.1 RealDeviceControlManager.java — 真实设备控制管理器

**文件路径：** `com/iflytek/ebg/aistudy/mdm/control/device/RealDeviceControlManager.java`

**职责：** 设备管控的核心协调器，管理整机管控全生命周期。

**关键组件：**
```java
appContext              → Context
singleTaskRunner        → 异步任务执行器
canLockDevice           → 检查是否可锁屏的回调
deviceControlQueryFactory → C1757d 配置查询工厂
deviceControlParser     → C1755b 配置解析器
deviceControlExecutor   → DeviceControlExecutor 执行器
configHolder            → UserDeviceControlConfigHolder 配置缓存
controlReminderParser   → ControlReminderParser 提醒弹窗
urlBlackListQuery       → C1766m 网址黑名单查询
controlStatusListeners  → 状态变化监听器列表
```

**核心方法：**

| 方法 | 功能 |
|------|------|
| `mo3701d(isForce, needDelay, needControl)` | 查询设备控制配置 |
| `mo3703f()` | 执行设备控制（锁屏/解锁判断） |
| `mo3702e()` | 获取当前锁定状态 (LockType) |
| `mo3699b()` | 获取今日倒计时时长 |
| `getOnceCountdownTime()` | 获取单次使用倒计时时长 |
| `m3679B(result)` | 更新管控结果并通知监听器 |
| `mo3705h(force)` | 刷新网址黑名单 |

**设备管控完整链路：**
```
RemotePush / Timer 触发
    │
    ▼
mo3701d(isForce, needDelay, needControl)
    │
    ▼
C1745d → SingleTaskRunner 异步执行
    │
    ├── 获取 userId (C2180b.m5677f())
    │   └── 为空 → 解除管控
    │
    ├── C0836c (deviceControlQueryX2) → 查询设备控制配置
    │   └── 从 ContentProvider / 网络 获取 DeviceControlInfo
    │
    ├── C1746e → 配置获取回调
    │   ├── UserDeviceControlConfigHolder.m3751d() → 缓存配置
    │   └── mo3703f() → 执行管控 (如果 needControl=true)
    │
    ▼
mo3703f() → C1742a → 执行管控任务
    │
    ├── UserDeviceControlConfigHolder.m3750a(userId) → 获取配置
    │
    ├── C2160c.mo5588f(userId) → 获取用户设备使用时长
    │
    ├── C1958e.getCurServerAndClientTime() → 获取服务器时间
    │
    ├── C1755b.m3746m(config, useData, serverTime) → 解析管控结果
    │   └── 返回 DeviceControlResult:
    │       ├── 锁定状态 (UNLOCK/TIME_OUT/DELAY_TIME_OUT/SINGLE_TIME_OUT/...)
    │       ├── 今日倒计时
    │       ├── 单次倒计时
    │       ├── 配置数据 (时长/休息时长等)
    │       └── userId
    │
    ├── DeviceControlExecutor.m3667b(context, result) → 执行管控
    │   └── m3661f(context, result) → 实际执行
    │       ├── UNLOCK → 清除锁定标记
    │       │   Settings 写入 IFLYTEK_XXJ_SETTINGS_GLOBAL_DEVICE_CONTROL_STATE = 0
    │       │   清除 IFLYTEK_XXJ_SETTINGS_GLOBAL_USER_CONTROL_STATE
    │       │   C1878f.m4248q() → 关闭锁屏窗口
    │       │
    │       └── 锁定状态 → 触发锁定
    │           ├── C1842a.m4076f() → 杀音频应用进程
    │           ├── Settings 写入 IFLYTEK_XXJ_SETTINGS_GLOBAL_DEVICE_CONTROL_STATE = 1
    │           ├── 写入 IFLYTEK_XXJ_SETTINGS_GLOBAL_USER_CONTROL_STATE (带userId+UUID)
    │           ├── DeviceStateUtil.m4465c() → 检查屏幕状态
    │           ├── LockUtil.m4471d() → 执行锁屏
    │           │
    │           └── 根据 LockType 执行不同策略:
    │               ├── TIME_OUT (整机时长到期)
    │               │   → 写入 SETTINGS_GLOBAL_DEVICE_CONTROL_DETAIL type=1
    │               │   → C1878f.m4247o(totalMinute)
    │               │
    │               ├── DELAY_TIME_OUT (临时时长)
    │               │   → 写入 type=2
    │               │   → C1878f.m4244i(tempMinute)
    │               │
    │               ├── SINGLE_TIME_OUT (单次使用)
    │               │   → 写入 type=3
    │               │   → C1878f.m4246m(restTime, restMinutes, useMinutes)
    │               │
    │               ├── OUT_OF_PERIOD (时段外)
    │               │   → 写入 type=4
    │               │   → C1878f.m4245k()
    │               │
    │               └── TEMP_OUT_OF_PERIOD (临时时段外)
    │                   → 写入 type=4
    │                   → C1878f.m4245k()
    │
    ├── ControlReminderParser.m3571k() → 显示锁屏前提醒弹窗
    │
    └── C1761h.m3765b() → 设置下次管控闹钟
```

#### 4.2.2 DeviceControlExecutor.java — 设备控制执行器

**文件路径：** `com/iflytek/ebg/aistudy/mdm/control/device/DeviceControlExecutor.java`

**职责：** 最底层的设备控制执行，直接与 Android 系统 API 交互。

**关键方法：**

| 方法 | 功能 | 涉及系统 API |
|------|------|-------------|
| `m3661f()` → `m3661f()` | 管控入口分发 | - |
| `m3657a()` | 音频管控 - 杀播放音频的应用 | AudioHelper + ProcessKill |
| `m3658c()` | 检查调试锁屏开关 | Settings.Global "iflytek_key_debug_close_lock" |
| `m3659d()` | 判断应用是否在白名单 | 检查QQ/微信/讯飞应用 |
| `m3660e()` | 检查是否有锁屏包 | PackageManager 检查 com.iflytek.lockscreen |
| `m3662g()` | 写入整机时长控制详情 | Settings.Global SETTINGS_GLOBAL_DEVICE_CONTROL_DETAIL |
| `m3663h()` | 写入时段外控制详情 | Settings.Global type=4 |
| `m3664i()` | 写入单次使用/休息详情 | Settings.Global type=3 |
| `m3665j()` | 写入临时时长详情 | Settings.Global type=2 |
| `m3666k()` | 清除用户控制状态 | Settings.Global IFLYTEK_XXJ_SETTINGS_GLOBAL_USER_CONTROL_STATE |

**Settings 全局状态标记：**

| Key | 值 | 含义 |
|-----|-----|------|
| `IFLYTEK_XXJ_SETTINGS_GLOBAL_DEVICE_CONTROL_STATE` | 0 | 设备未锁定 |
| `IFLYTEK_XXJ_SETTINGS_GLOBAL_DEVICE_CONTROL_STATE` | 1 | 设备已锁定 |
| `IFLYTEK_XXJ_SETTINGS_GLOBAL_USER_CONTROL_STATE` | "0\|userId\|UUID" | 解锁状态 |
| `IFLYTEK_XXJ_SETTINGS_GLOBAL_USER_CONTROL_STATE` | "1\|userId\|UUID" | 锁定状态 |
| `SETTINGS_GLOBAL_DEVICE_CONTROL_DETAIL` | JSON | 管控详情 (type/时长等) |
| `iflytek_key_debug_close_lock` | 1 | 关闭锁屏调试开关 |

**调试绕过点：** `m3658c()` 检查 `iflytek_key_debug_close_lock == 1` 时直接跳过锁屏逻辑。

#### 4.2.3 LockUtil.java — 锁屏工具类

**文件路径：** `com/iflytek/ebg/aistudy/mdm/screen/LockUtil.java`

**职责：** 执行实际锁屏操作。

**锁屏流程：**
```
m4471d(context)
    │
    ├── m4473a() → 检查是否处于特殊状态（如通话中）
    │   └── true → 跳过锁屏
    │
    ├── m4466a() → 检查系统是否禁用锁屏
    │   LockPatternUtils.isLockScreenDisabled(0)
    │   └── true → 跳过锁屏（系统锁屏被禁用）
    │
    └── m4467c() → 执行锁屏
        ├── 方案1: 有科大讯飞锁屏包 (com.iflytek.lockscreen)
        │   → 写入 familycircle_mdm_lockscreen 时间戳
        │   └── 由锁屏包处理
        │
        └── 方案2: 无锁屏包
            ├── m4468f() → 反射自动激活设备管理员
            │   DevicePolicyManager.setActiveAdmin(
            │       ComponentName(ScreenOffAdminReceiver.class),
            │       true,   // 强制激活
            │       0       // userId
            │   )
            │
            └── DevicePolicyManager.lockNow() → 系统锁屏
```

**m4469g() — WakeLock 获取：**
```java
PowerManager.WakeLock wakeLock = pm.newWakeLock(
    268435462,  // PARTIAL_WAKE_LOCK | ACQUIRE_CAUSES_WAKEUP | ON_AFTER_RELEASE
    "TAG"
);
wakeLock.acquire(1000L);  // 唤醒屏幕1秒
```

**m4472e() — 注册锁屏广播：**
```java
IntentFilter.addAction("com.iflytek.ebg.aistudy.mdm.action_lock_device_not_screenoff");
// 收到此广播 → 执行 m4471d() 锁屏
```

#### 4.2.4 C1878f.java — 锁屏窗口管理

**文件路径：** `com/iflytek/ebg/aistudy/mdm/lock/C1878f.java`

**职责：** 管理锁屏悬浮窗（LockWindow），显示倒计时和限制信息。

**关键方法：**

| 方法 | 功能 |
|------|------|
| `m4244i(totalMinute)` | 设置全天使用时长限制 |
| `m4245k()` | 清除锁屏（解锁） |
| `m4246m(onceRestCountdownTime, restMinutes, useMinutes)` | 设置单次使用/休息倒计时 |
| `m4247o(totalMinute)` | 设置时段控制 |
| `m4248q()` | 解除所有限制 |

### 4.3 网络访问控制 (NetVisit)

#### 4.3.1 NetVisitConfigParser.java — 网址拦截配置解析

**文件路径：** `com/iflytek/ebg/aistudy/mdm/control/netvisit/config/NetVisitConfigParser.java`

**职责：** 解析和缓存网址黑名单配置，生成最终拦截列表文件。

**内置白名单：**
```java
whiteUrlList = [
    "api.iflytek.com",        // 科大讯飞API
    "k12-swift.xunfeixxj.com",
    "xxjx3-aiplat.changyan.com",
    "aiplat.changyan.com",
    "ocr-aiplat.changyan.com",
    "www"
]
```

**配置加载流程：**
```
parse(isOpenControl, isOpenUpload, config)
    │
    ├── 支持全局列表 → 从 config 获取路径
    │   ├── globalControlBlacklistPath (URL 黑名单文件路径)
    │   └── globalControlDomainPath (域名黑名单文件路径)
    │
    ├── isOpenUpload=true → 加载不上报域名/URL列表
    │   ├── notReportWhitelistPath
    │   └── notReportDomainPath
    │
    ├── isOpenControl=false → 返回 NetVisitConfig.Close
    │
    └── isOpenControl=true → 更新黑名单
        ├── changeData() → 数据变更
        │   ├── 删除旧的黑名单文件
        │   ├── 解析URL文件和Domain文件
        │   ├── 合并设备域名列表
        │   └── 生成新的黑名单文件 (net_guard_url_file_{md5}.txt)
        │
        └── handleBlackList() → 加载黑名单到内存
```

**黑名单文件格式：**
- 每行一个 URL 或域名
- MD5 哈希生成文件名，防止冲突
- 自动清理旧文件

**`containsNotReportUrl()` — 不上报检查：**
```java
// 检查 URL 或域名是否在不上报列表中
// 用于判断该网络请求是否需要上报/拦截
```

#### 4.3.2 VPNNetVisitReceiver.java — VPN 网络访问接收器

**文件路径：** `com/iflytek/ebg/aistudy/mdm/control/netvisit/impl/vpn/VPNNetVisitReceiver.java`

**职责：** 通过 VPN 模式接收网络访问记录，实现网址拦截。

**广播注册：**
```java
IntentFilter.addAction("com.iflytek.aistudy.action.NET_GUARD");
context.registerReceiver(this, intentFilter);
```

**数据处理：**
```
onReceive(intent)
    │
    ├── 检查版本 key_net_record_version == "1"
    │
    ├── 获取记录 key_net_record_record (ArrayList<String>)
    │   └── 每条记录为 JSON 字符串
    │
    ├── 反序列化为 VPNNetRecordData 对象
    │
    └── onReceiver.invoke(record) → 回调处理
        ├── 检查 URL 是否在黑名单
        │   └── NetVisitConfigParser.containsNotReportUrl()
        │
        └── 如果在黑名单 → 拦截该请求
```

### 4.4 护眼控制 (EyeShield)

**涉及文件：** `com/iflytek/ebg/aistudy/mdm/eye/C1810c.java`, `C1812d.java`

**功能：**
- 护眼模式开关控制
- 防疲劳提醒
- 使用时长/休息时长配置
- 通过 `EyeProtectConfig` 模型从服务器获取

**与设备管控的关联：**
```
X2DeviceControlManager.C1751a.invoke2()
    │
    ├── C1810c.m3914c() → 获取护眼配置
    │   ├── eyeShieldControl: 护眼控制开关
    │   ├── antiFatigueStatus: 防疲劳状态
    │   ├── durationTime: 使用时长（分钟）
    │   └── restTime: 休息时长（分钟）
    │
    └── 如果护眼关闭 → C1878f.m4248q() 清除限制
        如果护眼开启 → C1878f.m4246m() 设置倒计时
```

### 4.5 截图/录屏管控

**涉及文件：** `com/iflytek/ebg/aistudy/mdm/push/screenshot/C1938a.java`, `com/iflytek/ebg/aistudy/mdm/screenshot/ScreenShotBackdoorActivity.java`

**指令类型：**
- `device_screenshot_control` — 截图管控
- `device_screenRecord_control` — 录屏管控
- `remote_screen_shot_control` — 远程截图

**功能：**
- 禁止/允许截图
- 禁止/允许录屏
- 远程截屏设备屏幕并上传

---

## 5. 数据层分析

### 5.1 ContentProvider 权限分析

#### 5.1.1 BusinessControlContentProvider

**URI:** `content://com.iflytek.ebg.aistudy.mdm_sdk/business_control`

**权限检查：**
```java
m5922c() {
    callingPkg = getCallingPackage()
    return callingPkg == "com.iflytek.ebg.aistudy.mdm"  // 仅检查包名
}
```

**弱点：**
- 仅检查 `getCallingPackage()` 字符串匹配
- 攻击者可通过 UID 共享、反射等手段伪造包名
- query/insert/update/delete 全部调用此检查

**可操作数据：**
- 所有业务管控配置 (key 通过 URI 路径指定)
- 支持通配符 `*` 遍历所有配置

#### 5.1.2 ControlDataContentProvider

**URI:** `content://com.iflytek.ebg.aistudy.mdm_sdk.control/control_data/1/*`

**权限检查：** **完全无权限检查**

**可操作数据：**
- 应用控制数据 (apps_control_data)
- 按应用包名分路径存储

**利用：**
```java
// 任意应用可读取/写入任意应用的控制数据
ContentResolver cr = getContentResolver();
cr.insert(Uri.parse("content://com.iflytek.ebg.aistudy.mdm_sdk.control/control_data/1/com.any.app"), values);
```

#### 5.1.3 StatisticalDataContentProvider

**URI:** `content://com.iflytek.ebg.aistudy.mdm_sdk.stat/statistical_data/{type}`

**权限检查：** **完全无权限检查**

**可查询数据：**

| type | 数据内容 |
|------|----------|
| 1 | 应用使用时长数据 (apps_use_data) |
| 2 | 设备使用时长数据 (device_use_data) |
| 3 | 设备控制配置 (device_control_config) |

#### 5.1.4 CommonDataContentProvider

**URI:** `content://com.iflytek.ebg.aistudy.mdm_sdk.common/common_data/{type}`

**权限检查：** **完全无权限检查**

**可查询数据：**

| type | 数据内容 | 查询参数 |
|------|----------|----------|
| 1 | 服务器时间差 | - |
| 2 | 网址拦截开关状态 | - |
| 3 | 用户登录记录 | selection=startTime&endTime |
| 4 | 用户使用时长详情 | selection=user_id |

**代码证据：**
```java
// 用户登录记录查询 (type=3)
String selection = cursor.getString(2); // startTime
String str3 = cursor.getString(3);       // endTime
C5052a.m17475d(Long.parseLong(selection), Long.parseLong(str3)).getRecords()

// 用户使用时长查询 (type=4)
String strM6049f = C2253r.f4472a.m6049f(Long.parseLong(selection))
// 返回该用户的使用时长字符串
```

### 5.2 数据存储格式

**所有管控数据均以 JSON 字符串形式存储，无加密：**

```json
// 应用控制数据示例
{
  "all_apps": {
    "disabled": false,
    "duration_limit": 120,
    "time_periods": ["08:00-12:00", "14:00-18:00"]
  },
  "com.tencent.mm": {
    "disabled": true,
    "reason": "家长管控"
  }
}

// 设备控制配置示例
{
  "device_duration": 240,       // 整机时长4小时
  "single_use_time": 30,        // 单次使用30分钟
  "single_rest_time": 10,       // 单次休息10分钟
  "time_periods": ["08:00-20:00"],
  "eye_shield": {
    "use_time": 30,
    "rest_time": 10
  }
}
```

---

## 6. 后门/调试入口分析

### 6.1 后门开关机制

**BaseBackdoorActivity.java — 后门入口检查：**
```java
private final boolean isOpenBackdoor() {
    // userdebug 版本直接开放所有后门
    if ("userdebug".equals(Build.TYPE)) return true;

    // 检查 Settings.Secure 标志位
    return Settings.Secure.getInt(
        contentResolver,
        "IFLYTEK_MDM_IS_OPEN_BACKDOOR",
        0
    ) == 1;
}
```

**激活方式：**
1. **userdebug 编译版本** — 后门直接可用，无需任何操作
2. **有系统权限** — `settings put secure IFLYTEK_MDM_IS_OPEN_BACKDOOR 1`

### 6.2 后门 Activity 清单

| Activity | URI Intent | 功能 |
|----------|-----------|------|
| BackdoorMainActivity | - | 后门主菜单，列出所有后门入口 |
| AccountBackdoorActivity | - | 账号管理 — 查看用户登录记录(按天/周/全部) |
| NetVisitBackdoorActivity | - | 上网管控配置 — 修改网址黑名单/白名单 |
| AppUseTimeBackdoorActivity | - | 应用使用时长管理 — 查看/修改各应用时长 |
| UnlockTimesBackdoorActivity | - | 解锁次数管理 — 查看/修改解锁次数限制 |
| DeviceStateBackdoorActivity | - | 设备状态管理 — 查看/设置设备状态 |
| HeadsetBackdoorActivity | - | 耳机管理 — 耳机插拔状态/管控 |
| TimeCalcBackdoorActivity | - | 时间计算策略 — 使用时长计算逻辑 |
| ScreenShotBackdoorActivity | - | 截图管理 — 截图拦截/远程截图 |

### 6.3 AccountBackdoorActivity 详解

**文件路径：** `com/iflytek/ebg/aistudy/mdm/usage/account/backdoor/AccountBackdoorActivity.java`

**功能：** 查看用户登录记录。

**三个时间范围按钮：**
```java
btnDay → m4725f(服务器零点时间, 当前时间)       // 今日登录记录
btnWeek → m4725f(当前时间-7天, 当前时间)        // 近7天登录记录
btnAll → m4725f(0, 当前时间)                    // 全部登录记录
```

**数据来源：**
```java
C5052a.m17475d(startTime, endTime).getRecords()
// 返回 UserLoginRecord 列表
// 包含: userId, loginTime, logoutTime, deviceInfo 等
```

---

## 7. 广播接收器分析

### 7.1 AlarmTriggerReceiver.java

**文件路径：** `com/iflytek/ebg/aistudy/mdm/receiver/AlarmTriggerReceiver.java`

**注册方式：** PendingIntent 由 MDM 自身通过 AlarmManager 注册

**触发逻辑：**
```
onReceive(intent)
    │
    ├── 检查 intent.mPackageName == 自身包名
    │
    ├── mGroupId="deviceControl" && mBizId="wakeUpToCheck"
    │   → m3398o() → 整机管控唤醒
    │   → RealDeviceControlManager.mo3703f() 执行管控
    │   → C1692a.m3381i() 刷新应用管控
    │
    └── mGroupId="appControl" && mBizId="wakeUpToCheck"
        → m3399p() → 应用管控唤醒
        → C1692a.m3381i() 刷新应用管控
```

**绕过风险：** Intent 中 `mPackageName` 可被伪造，但需要 PendingIntent 机制。

### 7.2 ShutdownAlarmReceiver.java

**文件路径：** `com/iflytek/ebg/aistudy/mdm/shutdown/ShutdownAlarmReceiver.java`

**触发广播：** `com.iflytek.ebg.aistudy.mdm.autoshutdown`

**关机流程：**
```
onReceive(intent)
    │
    ├── type="shutdown"
    │   ├── 检查当前时间 vs 目标时间（容差5分钟）
    │   ├── 未到时 → 重新设置闹钟
    │   └── 已到时 → m4559i() 执行关机
    │       └── C1971c.m4603C("13024") → 关机指令
    │
    └── type="set"
        └── 设置定时关机闹钟
```

**安全风险：** 广播无权限保护，但关机需要系统权限。

### 7.3 LockUtil 注册广播

**广播 Action：** `com.iflytek.ebg.aistudy.mdm.action_lock_device_not_screenoff`

**功能：** 收到此广播 → 执行锁屏

---

## 8. 安全隐患汇总

### 8.1 高危隐患

| 编号 | 模块 | 问题描述 | 文件位置 | 可利用性 |
|------|------|----------|----------|----------|
| H1 | ContentProvider | 4个Provider无权限或弱权限校验，任意应用可读写管控配置和使用数据 | BusinessControlContentProvider.java, ControlDataContentProvider.java, StatisticalDataContentProvider.java, CommonDataContentProvider.java | **高** |
| H2 | UniversalTransferService | exported AIDL 接口无认证，可注入伪造日志和手势数据 | UniversalTransferService.java:32-145 | **高** |
| H3 | DumpService | exported dump 接口泄露系统内部信息 | DumpService.java:14-32 | **高** |
| H4 | Push远程指令 | 20+指令类型可远程控制设备全生命周期，服务端可完全接管设备 | AIStudyPushMessageReceiverImpl.java, ControlInstructionHandler.java | **依赖服务器** |

### 8.2 中危隐患

| 编号 | 模块 | 问题描述 | 文件位置 | 可利用性 |
|------|------|----------|----------|----------|
| M1 | 后门Activity | userdebug版本或Settings标志位可激活9个后门页面 | BaseBackdoorActivity.java:13-34 | **需系统权限** |
| M2 | AlarmTriggerReceiver | 可伪造Intent触发管控刷新逻辑 | AlarmTriggerReceiver.java:18-43 | **中** |
| M3 | isUseLocalConfig | VPNNetVisitControl静态标志位可绕过远程配置 | VPNNetVisitControl.java | **需代码执行** |
| M4 | LockUtil | 反射自动激活设备管理员，无需用户确认 | LockUtil.java:57-69 | **高** |
| M5 | Settings调试开关 | iflytek_key_debug_close_lock=1可关闭锁屏 | DeviceControlExecutor.java:93-98 | **需Settings写入** |

### 8.3 低危隐患

| 编号 | 模块 | 问题描述 | 文件位置 | 可利用性 |
|------|------|----------|----------|----------|
| L1 | 数据存储 | 管控数据全部明文JSON存储，无加密 | 多个ContentProvider | **需root** |
| L2 | ShutdownAlarmReceiver | 无权限保护的关机广播 | ShutdownAlarmReceiver.java:32-201 | **中** |
| L3 | WakeLock | 锁屏时获取的WakeLock标签为"TAG"，不规范 | LockUtil.java:73-81 | **低** |

### 8.4 安全隐患数据流图

```
┌──────────────────────────────────────────────────────────────┐
│                      攻击面分析                               │
│                                                              │
│  ┌─────────────────┐    无认证     ┌─────────────────────┐   │
│  │  第三方应用      │ ──────────→ │  ControlData        │   │
│  │                 │              │  ContentProvider    │   │
│  │  (任意UID)       │              │  (读写应用控制数据)  │   │
│  └────────┬────────┘              └─────────────────────┘   │
│           │                                                  │
│           │              无认证     ┌─────────────────────┐   │
│           │ ──────────→ │  StatisticalData   │   │
│           │              │  ContentProvider    │   │
│           │              │  (读取使用统计)     │   │
│           │              └─────────────────────┘   │
│           │                                                  │
│           │              无认证     ┌─────────────────────┐   │
│           │ ──────────→ │  CommonData        │   │
│           │              │  ContentProvider    │   │
│           │              │  (读取登录记录/时长) │   │
│           │              └─────────────────────┘   │
│           │                                                  │
│           │              bindService  ┌─────────────────────┐   │
│           │ ──────────→ │  UniversalTransfer │   │
│           │              │  Service (AIDL)     │   │
│           │              │  注入日志/手势数据   │   │
│           │              └─────────────────────┘   │
│           │                                                  │
│           │              弱包名检查  ┌─────────────────────┐   │
│           │ ──────────→ │  BusinessControl   │   │
│           │              │  ContentProvider    │   │
│           │              │  (读写所有管控配置)  │   │
│           │              └─────────────────────┘   │
│           │                                                  │
│           │              dumpsys      ┌─────────────────────┐   │
│           │ ──────────→ │  DumpService        │   │
│           │              │  (系统信息泄露)     │   │
│           │              └─────────────────────┘   │
│                                                              │
│  ┌─────────────────┐    需系统权限  ┌─────────────────────┐   │
│  │  Settings写入    │ ──────────→ │  IFLYTEK_MDM_IS_    │   │
│  │                 │              │  OPEN_BACKDOOR=1   │   │
│  │  (adb shell /   │              │  激活9个后门页面    │   │
│  │   root权限)      │              └─────────────────────┘   │
│           │                                                  │
│           │              Settings写入  ┌─────────────────────┐   │
│           │ ──────────→ │  iflytek_key_debug  │   │
│           │              │  _close_lock=1     │   │
│           │              │  关闭锁屏功能      │   │
│           │              └─────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

---

## 9. 修复建议

### 9.1 ContentProvider 权限加固

**当前状态：** 4个Provider中有3个完全无权限检查，1个仅检查包名。

**建议方案：**
```xml
<!-- AndroidManifest.xml -->
<permission
    android:name="com.iflytek.ebg.aistudy.mdm.permission.MDM_DATA"
    android:protectionLevel="signature" />

<provider
    android:name="...ControlDataContentProvider"
    android:exported="true"
    android:permission="com.iflytek.ebg.aistudy.mdm.permission.MDM_DATA" />
```

### 9.2 关闭不必要的 exported 组件

**建议移除 exported 的组件：**
- `DumpService` — 不需要外部绑定
- `UniversalTransferService` — 仅需内部通信
- `AlarmTriggerReceiver` — 仅由自身 AlarmManager 触发

```xml
<service android:name="...DumpService" android:exported="false" />
<service android:name="...UniversalTransferService" android:exported="false" />
```

### 9.3 关闭生产版本后门

**建议：**
- 生产版本彻底移除所有 Backdoor Activity
- 或将后门开关从 Settings 改为编译时配置（BuildConfig.DEBUG）

### 9.4 Push 指令签名验证

**建议：**
- 远程指令增加 HMAC 签名校验
- 增加时间戳防重放攻击
- 指令内容加密传输

### 9.5 数据加密存储

**建议：**
- 使用 Android Keystore 加密敏感管控配置
- 使用 EncryptedSharedPreferences 替代明文 SharedPreferences
- 数据库使用 SQLCipher 加密

### 9.6 广播权限保护

**建议：**
```xml
<permission
    android:name="com.iflytek.ebg.aistudy.mdm.permission.MDM_BROADCAST"
    android:protectionLevel="signature" />

<receiver
    android:name="...AlarmTriggerReceiver"
    android:permission="com.iflytek.ebg.aistudy.mdm.permission.MDM_BROADCAST" />
```

### 9.7 移除调试开关

**建议：**
- 移除 `iflytek_key_debug_close_lock` Settings 键
- 或将其改为仅 debug 编译可用

---

## 附录 A：关键代码文件清单

| 层级 | 文件路径 | 功能 |
|------|----------|------|
| 入口 | `app/MDMApplication.java` | 应用初始化入口 |
| 入口 | `mdm/service/SystemActionReceiver.java` | 开机广播接收 |
| 入口 | `mdm/AIStudyPushMessageReceiverImpl.java` | Push 指令接收 |
| 服务 | `mdm/service/MDMService.java` | 主服务(空壳) |
| 服务 | `mdm/service/DumpService.java` | 系统 dump |
| 服务 | `mdm/service/UniversalTransferService.java` | AIDL 数据传输 |
| 管控 | `mdm/control/app/C1692a.java` | 应用管控入口 |
| 管控 | `mdm/control/app/app_control/X2AppControl.java` | 应用控制实现 |
| 管控 | `mdm/control/app/app_control/executor/C1718b.java` | 应用管控执行 |
| 管控 | `mdm/control/device/RealDeviceControlManager.java` | 设备管控管理器 |
| 管控 | `mdm/control/device/DeviceControlExecutor.java` | 设备管控执行 |
| 管控 | `mdm/control/device/X2DeviceControlManager.java` | X2设备管控 |
| 管控 | `mdm/screen/LockUtil.java` | 锁屏工具类 |
| 管控 | `mdm/lock/C1878f.java` | 锁屏窗口管理 |
| 管控 | `mdm/push/control/ControlInstructionHandler.java` | Push指令处理 |
| 管控 | `mdm/push/control/C1935a.java` | Push指令注册 |
| 网络 | `mdm/control/netvisit/config/NetVisitConfigParser.java` | 网址配置解析 |
| 网络 | `mdm/control/netvisit/impl/vpn/VPNNetVisitReceiver.java` | VPN网络拦截 |
| 数据 | `provider/BusinessControlContentProvider.java` | 业务管控数据 |
| 数据 | `provider/ControlDataContentProvider.java` | 应用控制数据 |
| 数据 | `provider/StatisticalDataContentProvider.java` | 统计数据 |
| 数据 | `provider/CommonDataContentProvider.java` | 公共数据 |
| 后门 | `mdm/backdoor/BaseBackdoorActivity.java` | 后门基类 |
| 后门 | `mdm/backdoor/BackdoorMainActivity.java` | 后门主菜单 |
| 后门 | `mdm/usage/account/backdoor/AccountBackdoorActivity.java` | 账号后门 |
| 广播 | `mdm/receiver/AlarmTriggerReceiver.java` | 闹钟触发管控 |
| 广播 | `mdm/shutdown/ShutdownAlarmReceiver.java` | 定时关机 |
| 提醒 | `mdm/control/app/applet_control/window/ControlReminderParser.java` | 管控提醒弹窗 |

---

## 附录 B：Settings 全局键值清单

| Key | 类型 | 含义 | 写入位置 |
|-----|------|------|----------|
| `IFLYTEK_XXJ_SETTINGS_GLOBAL_DEVICE_CONTROL_STATE` | int | 0=未锁定, 1=已锁定 | DeviceControlExecutor |
| `IFLYTEK_XXJ_SETTINGS_GLOBAL_USER_CONTROL_STATE` | String | "状态\|userId\|UUID" | DeviceControlExecutor |
| `SETTINGS_GLOBAL_DEVICE_CONTROL_DETAIL` | String | JSON管控详情 | DeviceControlExecutor |
| `iflytek_key_debug_close_lock` | int | 1=关闭锁屏(调试) | DeviceControlExecutor检查 |
| `familycircle_mdm_lockscreen` | long | 锁屏时间戳 | LockUtil |
| `IFLYTEK_MDM_IS_OPEN_BACKDOOR` | int | 1=开启后门 | BaseBackdoorActivity检查 |

---

*本报告基于 jadx 反编译源码静态分析，所有结论均来自代码逻辑推断。*
