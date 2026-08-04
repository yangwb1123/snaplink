# 架构分析报告：五项已验证的扩展方向

> **分析师：** 资深架构师 Agent  
> **日期：** 2026-07-11  
> **基于：** 全局核验报告（五项产品级扩展方向验证结果）  
> **状态：** 核验报告 4/5 完全确认，1/5 部分确认（已修正）  
> **前置分析参考：** `docs/architect-analysis-v6-five-directions.md`（后端基础设施方向）  
> **输出格式：** 本文件为独立架构级分析，后续可拆分为 `docs/feature-spec-*.md`

---

## 1. 架构评估

### 1.1 当前架构的优势

与前置分析一致的评估——本项目架构成熟度很高。与本次验证报告特别相关的优势：

| 优势 | 表现 | 与本报告的直接关联 |
|------|------|-------------------|
| **分离关注点清晰** | 后端/前端完全分离——SPA 通过 REST API 与 SSO 后端通信，无模板耦合 | 验证报告中的前端缺口（i18n、信任设备、批量管理）均可独立修复，不影响后端核心 |
| **后端 i18n 基础设施完整** | `shared/i18n` 包提供了 `Localizer` 接口、`Bundle` 加载器、`PreferredLocale` 解析器 | i18n 方向只需扩展 SPA 层，后端已就绪 |
| **信任设备后端全线就绪** | `core.TrustedDeviceStore` SPI + memory/sqlite 实现 + `/me/devices` 路由 + 审计事件 | 信任设备方向只需 SPA UI 接线，零后端变更 |
| **自包含的 Admin SPA** | 无前端框架依赖（纯 Vanilla JS），可直接扩展而不引入构建工具链 | 批量管理方向可在现有架构内扩展，不需 Webpack/Vite 迁移 |
| **代码生成器架构清晰** | Go 模板 + `embed.FS` + CLI 子命令，分离模板和入口逻辑 | 修复生成器不需框架重写，只需填充 TODO |

### 1.2 当前架构的局限性

从验证报告揭示的五个方向看，当前架构有以下局限：

#### 局限一：SPA 层零国际化（硬缺口）

```
┌─────────────────────────────────────────────┐
│  backend  i18n layer                         │
│  ┌─────────────────────────────────────┐    │
│  │ shared/i18n/i18n.go                │ ✅ │
│  │   - Localizer interface             │    │
│  │   - Bundle + MemoryLocalizer        │    │
│  │   - PreferredLocale()               │    │
│  │   - en.json (5 keys), es.json (5)   │    │
│  └─────────────────────────────────────┘    │
│                    ↓                         │
│  interfaces/sso/server_errors.go            │
│    - errorBody → Localizer → lang attr      │
│                    ↓                         │
│  4个 SPA 硬编码 lang="en"                   │
│  零 i18n 函数调用                           │
│  无 navigator.language 读取                  │
└─────────────────────────────────────────────┘
```

**根因：** 项目定位从"Go SDK + demo SPA"演进为"生产级身份平台"过程中，后端 SPI 先行，前端同步滞后。4 个 SPA 最初是功能演示（proof-of-concept），未经历国际化设计阶段。

#### 局限二：前端-后端功能不对等（信任设备）

信任设备是架构上最典型的"后端完备、前端缺失"案例：

| 层 | 就绪状态 |
|---|---|
| SPI 定义 | ✅ `core.TrustedDeviceStore` + `core.TrustedDevice` |
| 后端实现 | ✅ memory + sqlite |
| HTTP 路由 | ✅ `POST /auth/login` 信任设备检查 + `/me/devices*` |
| 审计事件 | ✅ `EventMFASkippedTrustedDevice` |
| Login SPA 信任设备复选框 | ❌ 不存在 |
| Portal SPA 设备管理面板 | ❌ 不存在 |

**根因：** 后端开发按 SPI 驱动模式推进，每个 store 都有测试覆盖；前端开发是"刚好满足演示"，信任设备的 MFA 跳过逻辑在后端完成但没有前端入口让用户触发它。

#### 局限三：Admin SPA 缺少企业级运维能力

当前 Admin SPA 严格限定在单资源 CRUD。缺乏：

| 能力 | 缺失的代价 |
|---|---|
| 批量用户操作（导入/导出/批量停用） | 客户对接期需要手动逐个操作或写脚本调 API |
| CSV 导入 | 没有批量创建用户的入口 |
| 搜索（用户/客户端/租户） | 除了审计日志，管理面板只能分页浏览 |
| 审计日志导出 | 合规审查需要导出审计日志，目前只能翻页查看 |

**根因：** Admin SPA 设计时对标的是"演示管理面板"而非"生产管理控制台"。审计日志有搜索是因为合规审查需求的早期识别。

#### 局限四：代码生成器半成品状态

`sso-ctl generate` 的模板系统有 31 个 TODO，涉及 4 类模板（authenticator、store、handler、grant）。核心问题：

| 模板类型 | TODO 数 | 关键缺失 |
|---|---|---|
| `templates.go` | 13 | Authenticator 的 `Authenticate()` 返回 `not implemented`；Store 的所有 CRUD 注释掉；无存储后端连接 |
| `templates_handler.go` | 18 | Handler 所有 GET/POST/PUT/DELETE 返回占位 JSON；Grant 的 `HandleToken` 返回 `not implemented` |

**根因：** 代码生成器是"脚手架生成"功能——目标是生成可编译的骨架，开发者需填充业务逻辑。但当前状态是骨架甚至没有正确的类型签名（Authenticator 返回 `nil, error` 而非 `nil, sentinel`），导致开发者即使填充了代码也可能因哨兵值错误而在运行时静默失败。

#### 局限五：HTTP/2 的硬编码禁用

```
// cmd/sso-server/main_helpers.go:120-121
if os.Getenv("GODEBUG") == "" {
    os.Setenv("GODEBUG", "http2server=0")
}
```

**根因：** 这是一个运维决策（"reverse proxy 场景下 HTTP/2 server 没有收益"）被硬编码为全局默认值。缺乏配置化手段的代价：需要 HTTP/2 的场景（gRPC、APNS/2 HTTP/2 push、直接面向客户端的部署）必须通过环境变量 override，且无法在 `config.yaml` 中控制。

### 1.3 架构债务评估（新增方向）

| 债务 | 严重度 | 影响范围 | 修复状态 |
|------|--------|---------|---------|
| SPA 全部硬编码 `lang="en"` | 🟡 中 | 4 个 SPA × 所有 UI 文本 | 全新开发（0→约 400 行/SPA） |
| Login SPA MFA 视图方法标签硬编码 | 🟢 低 | Login SPA | 纳入 i18n 方向修复 |
| Portal SPA 信任设备管理缺失 | 🟡 中 | Portal SPA | 后端已就绪，仅需 UI（~200 行） |
| Admin SPA 无批量操作 | 🟠 高 | Admin SPA | 需后端 API + 前端 UI（~600 行） |
| 代码生成器 31 个 TODO | 🟡 中 | 开发者体验 | 填充 TODO + 修复哨兵值（~150 行） |
| HTTP/2 硬编码禁用 | 🟢 低 | 服务器配置 | 加 config 字段（~30 行） |

> **整体判断：** 这五个方向的架构债务属于**成长型债务**（evolutionary debt）——系统从"SDK + demo"向"产品级平台"演进中，前端和工具链的投入滞后于后端。所有债务都可以在当前架构内修复，不需要架构重组。

---

## 2. 扩展方向

### 2.1 方向一：SPA 国际化（i18n）——P0

#### 为什么需要（业务价值）

| 价值类型 | 说明 |
|---------|------|
| **市场覆盖** | 全球身份平台需要支持多语言登录页面——这是 B2B 客户采购的准入条件 |
| **合规** | GDPR/金融监管要求以用户理解的语言呈现授权同意信息 |
| **用户体验** | 登录页面的错误信息（"密码错误"）若用非用户语言显示，会增加支持成本 |
| **竞争差异** | 大多数 SSO 产品（Okta、Azure AD、Auth0）都支持多语言登录页面。这是市场基准 |

#### 核心挑战与技术难点

| 挑战 | 难度 | 说明 |
|------|------|------|
| **消息外化** | L | 4 个 SPA 中所有用户可见字符串需要提取为 key。Admin SPA（1385 行）工作量最大，Login SPA（694 行）次之 |
| **翻译管理** | M | 需要决定翻译文件的存储位置（嵌入 SPA vs 后端下发 vs CDN 加载） |
| **SPA 架构** | M | 当前 4 个 SPA 都是 Vanilla JS（无框架），不能使用 react-intl/vue-i18n。需要自建轻量 i18n 引擎 |
| **RTL 支持** | M | 如果支持阿拉伯语/希伯来语，CSS 需要 `dir="rtl"` 适配——当前样式表无此设计 |
| **动态内容** | M | 授权同意页面的 scope 描述来自后端（`consent_required` 响应体）——这些字符串也需要翻译 |

#### 架构设计

**核心决策：前端自包含翻译 vs 后端下发翻译**

| 方案 | 优点 | 缺点 |
|------|------|------|
| **A: SPA 内置翻译（推荐）** | 零网络开销；离线可用；与现有 SPA 自包含架构一致 | 翻译更新需重新部署 SPA（FS 嵌入） |
| **B: 后端下发翻译（通过 API）** | 翻译热更新；可接入 TMS（翻译管理系统） | 增加 API 延迟；SPA 启动时需要先加载翻译 |

**推荐：方案 A**。原因：
1. 4 个 SPA 都是通过 `embed.FS` 嵌入二进制——翻译文件可同样嵌入
2. 翻译变更通常跟随代码发布，不需要热更新
3. 后端已有 `Localizer` SPI——如果未来需要热更新翻译，可以扩展方案 B（翻译从后端 API 懒加载，缓存 localStorage）

**轻量 i18n 引擎设计（~50 行/SPA）：**

```javascript
// 轻量级 i18n 模块 —— 每个 SPA 自包含
var i18n = (function() {
  var locale = navigator.language || navigator.languages?.[0] || 'en';
  var lang = locale.split('-')[0]; // 'en-US' → 'en'

  // 翻译表 —— 构建时生成，嵌入 SPA
  var messages = {
    'login.title':     { en: 'Sign in',                  es: 'Iniciar sesión',     ja: 'サインイン' },
    'mfa.title':       { en: 'Verify your identity',     es: 'Verifica tu identidad' },
    'mfa.totp_label':  { en: 'Authenticator app (TOTP)', es: 'App de autenticación (TOTP)' },
    // ...
  };

  function t(key, fallback) {
    var msg = messages[key];
    if (!msg) return fallback || key;
    return msg[lang] || msg['en'] || fallback || key;
  }

  function langAttr() { return lang; }

  return { t: t, lang: langAttr, locale: function() { return locale; } };
})();
```

**翻译表嵌入方案：**

```
interfaces/web/
├── login/
│   ├── index.html          ← <html lang=""> 由 JS 动态设置
│   ├── app.js              ← 引用 i18n.js
│   ├── i18n.js             ← 轻量引擎 + login 特有翻译
│   ├── i18n.en.json        ← 构建时合并到 i18n.js
│   ├── i18n.es.json
│   └── style.css
├── admin/
│   ├── ...                 ← 同上模式，admin 特有翻译
│   └── i18n.js
├── portal/
│   └── i18n.js
└── developer/
    └── i18n.js
```

**翻译 key 管理策略：**

| 策略 | 建议 |
|------|------|
| key 命名 | `{页面}.{组件}.{描述}` 例如 `login.mfa.totp_label`、`admin.user.create_title` |
| 默认语言 | 英语（`en`）作为 base，JS 代码中 `t('key', 'English fallback')` |
| 翻译文件格式 | JSON，每个 SPA 独立（避免 4 个 SPA 共享一个大文件） |
| 未翻译 key 回退 | `lang` 找不到 → `en` 回退 → key 本身作为最后回退 |
| 动态内容翻译 | 后端 `consent_required` 响应体中的 scope 描述由后端 i18n 处理 |

#### 对现有系统的影响

| 影响项 | 程度 |
|--------|------|
| 代码变更 | 4 个 SPA 的 `app.js` 需要外化字符串 + 添加 `i18n.js`（总计约 400-600 行） |
| 构建集成 | 需要脚本从 JSON 生成 JS 翻译表（可放在 `Makefile` 或 `Taskfile.yml` 中） |
| 后端变更 | **零变更**——现有 `Localizer` SPI + `accept_language.go` 用于错误响应，SPA 面使用前端 i18n |
| 性能影响 | `i18n.js` 约 5-15 KB（gzip 后 2-5 KB），一次 HTTP 请求 |
| 向后兼容 | 完全兼容——未配置翻译文件的部署自动回退到英语硬编码字符串 |

---

### 2.2 方向二：信任此设备 UX（P0）

#### 为什么需要（业务价值）

这是**投入产出比最高的方向**——后端已 100% 就绪，仅需前端 UI。

| 价值 | 说明 |
|------|------|
| **用户体验提升** | 用户不需要每次登录都输入 MFA——这是行业标准做法（"记住此设备 30 天"） |
| **安全与便利的平衡** | MFA 是安全要求，但每次登录都要求 MFA 会降低生产力。信任设备实现"首次 MFA，后续跳过" |
| **功能完备性** | SSO 产品缺少"信任此设备"复选框在 2026 年是不完整的 |
| **后端投资回报** | 后端团队投入了完整 SPI + 实现 + 路由 + 审计事件 + 端到端测试，只差 UI 就能产生用户价值 |

#### 核心挑战与技术难点

| 挑战 | 难度 | 说明 |
|------|------|------|
| **Login SPA 的 MFA 视图添加复选框** | L | 只需在 MFA 视图添加一个 checkbox + label |
| **信任设备令牌管理** | L | Login SPA 需要在 MFA 成功后将 `trust_device` 参数传回 `/auth/mfa` |
| **Portal SPA 设备面板** | M | 需要添加"已信任设备"列表 + 撤销按钮 |
| **设备命名** | M | Portal SPA 有 `deviceHint()` 函数（从 User-Agent 推断设备名）——但当前只用于 session 列表，需在设备面板复用 |

#### 架构设计

**Login SPA 变更（最小化）：**

```javascript
// 在 MFA 视图中添加：
// <label><input type="checkbox" id="mfa-trust-device"> Trust this device for 30 days</label>

// 在 mfa-btn 点击处理中：
var body = {
  mfa_challenge_id: currentMFAChallengeID,
  method:           selectedMFAMethod,
  credential:       { code: code },
  trust_device:     document.getElementById('mfa-trust-device').checked  // ← 新增
};
```

**Portal SPA 变更（设备管理面板）：**

```javascript
// 新增 /me/devices API 调用
function loadDevices() {
  apiFetch('/me/devices', { headers: authHeaders() }).then(function(resp) {
    if (resp.ok) {
      renderDeviceList(resp.body.devices);
    }
  });
}

function revokeDevice(deviceID) {
  if (!confirm('Revoke trust for this device?')) return;
  apiFetch('/me/devices/' + encodeURIComponent(deviceID), {
    method: 'DELETE',
    headers: authHeaders(),
  }).then(function(resp) {
    if (resp.ok) loadDevices();
  });
}
```

**复用 `deviceHint()`：** Portal SPA 的 `deviceHint(ua)` 函数当前只在 session 列表中使用。设备管理面板应复用此函数显示设备名。如果 `TrustedDevice` 中未存储 User-Agent，后端 `/me/devices` 需要补充返回。

#### 对现有系统的影响

| 影响项 | 程度 |
|--------|------|
| Login SPA 变更 | + ~30 行（添加 checkbox + 发送 trust_device 参数） |
| Portal SPA 变更 | + ~100 行（设备列表 + 撤销面板） |
| 后端变更 | **零变更**——所有 API 已就绪 |
| 审计事件 | 已存在 `EventMFASkippedTrustedDevice` |
| 端到端测试 | 已有 `rootcov_trusted_devices_test.go`——前端变更后验证相同流程 |

---

### 2.3 方向三：Admin Console 批量管理能力（P1）

#### 为什么需要（业务价值）

| 价值 | 说明 |
|------|------|
| **企业采购的准入门槛** | 没有批量用户导入/导出的管理控制台在 2026 年不符合企业级身份管理产品标准 |
| **运营效率** | 客户 onboarding 时可能需要一次导入 1000+ 用户——逐个创建不可接受 |
| **合规需求** | 审计日志导出是 SOC2/ISO 27001 审查的标准要求 |
| **搜索发现性** | 管理数百个客户端/租户时，分页浏览而无搜索是不可用的 |

#### 核心挑战与技术难点

| 挑战 | 难度 | 说明 |
|------|------|------|
| **批量 API 设计** | M | 当前 Admin API 以单资源 CRUD 设计。批量操作需要新的端点或扩展现有端点 |
| **异步作业模型** | M | 批量导入 10,000 用户不能同步完成——需要异步作业 + 进度反馈 |
| **CSV 解析** | L | CSV 解析本身简单，但错误报告（第几行哪个字段无效）需要设计 |
| **搜索后端支持** | M | 当前只有审计日志有搜索（`/admin/audit?q=`）。用户/客户端/租户搜索需要后端新增查询参数 |
| **审计日志导出** | L | `/admin/audit` 已有分页和搜索——加上 `Accept: text/csv` 或 `/admin/audit/export` |
| **前端表格组件** | M | Admin SPA 使用自定义表格渲染（非表格库），批量选择行需要扩展 |

#### 架构设计

**阶段一：API 扩展（后端）**

**批量操作 API 模式：** 不创建新的 REST 资源，而是为现有资源添加批量端点：

```
POST   /admin/users/batch         批量创建用户（请求体: { users: [...] }）
POST   /admin/users/batch/delete  批量删除用户（请求体: { ids: [...] }）
GET    /admin/users/export        导出用户列表为 CSV
GET    /admin/audit/export        导出审计日志为 CSV（已有搜索参数复用）
```

**异步作业模型（使用现有基础设施）：**

```go
// 批量操作返回作业 ID
type BatchJob struct {
    ID        string    `json:"id"`
    Status    string    `json:"status"`    // pending | running | completed | failed
    Total     int       `json:"total"`
    Processed int       `json:"processed"`
    Errors    []BatchError `json:"errors,omitempty"`
    CreatedAt time.Time `json:"created_at"`
}

type BatchError struct {
    Line  int    `json:"line"`  // CSV 行号
    Field string `json:"field,omitempty"`
    Error string `json:"error"`
}
```

**搜索扩展：** 为 `/admin/users`、`/admin/clients`、`/admin/tenants` 添加 `?q=` 查询参数，通过后端 store 的搜索能力实现。

**阶段二：前端 UI**

```javascript
// 批量选择模式
var selectedUserIds = {};

function toggleUserSelection(id) {
  if (selectedUserIds[id]) delete selectedUserIds[id];
  else selectedUserIds[id] = true;
  updateBatchActionsUI();
}

function batchDeleteUsers() {
  var ids = Object.keys(selectedUserIds);
  if (!confirm('Delete ' + ids.length + ' users?')) return;
  apiFetch('/admin/users/batch/delete', {
    method: 'POST',
    headers: Object.assign({'Content-Type': 'application/json'}, authHeaders()),
    body: JSON.stringify({ ids: ids }),
  }).then(function(resp) {
    if (resp.ok) { loadUsers(); selectedUserIds = {}; }
  });
}
```

**CSV 导入前端流程：**

```
用户点击"导入" → 文件选择对话框（accept=".csv"）
    → JS 读取 File API → 预览前 5 行
    → 用户确认列映射 → POST /admin/users/batch
    → 返回作业 ID → 轮询作业状态 → 显示进度条 → 完成后显示错误报告
```

#### 对现有系统的影响

| 影响项 | 程度 |
|--------|------|
| 后端新端点 | 5-8 个新端点（batch create/delete，export for users+audit，search 参数扩展） |
| 后端异步作业 | 新的 `BatchJobStore` SPI + memory 实现（可复用部分现有作业执行器） |
| Admin SPA 变更 | ~300 行新代码（批量选择模式 + CSV 导入 + 搜索框 + 导出按钮） |
| 性能影响 | 批量操作异步处理，不阻塞请求路径 |
| 向后兼容 | 完全兼容——单资源 CRUD 端点不变 |

---

### 2.4 方向四：代码生成器修复与增强（P2）

#### 为什么需要（技术价值）

| 价值 | 说明 |
|------|------|
| **开发者体验（DX）** | `sso-ctl generate` 是 SDK 使用者的第一个接触点——生成半成品代码给开发者留下"项目不成熟"的第一印象 |
| **生产力** | 31 个 TODO 意味着开发者生成代码后需要手动阅读模板找到 TODO 并填充——比从零开始写还慢 |
| **生态建设** | 一个好的生成器帮助第三方开发者为 SSO 编写 authenticator/store/handler/grant——这是生态系统增长的基础 |

#### 核心挑战与技术难点

| 挑战 | 难度 | 说明 |
|------|------|------|
| **TODO 补全** | L | 填充 31 个 TODO 是纯工作量，但关键是选择正确的默认实现 |
| **哨兵值正确性** | M | Authenticator 的 `Authenticate()` 返回 `nil, error` 而不是 `nil, core.ErrUserNotFound`——默认返回错误应该使用正确的 sentinel |
| **Store CRUD 骨架** | M | 被注释掉的 CRUD 方法需要恢复，至少生成 `return nil, fmt.Errorf("not implemented")` 占位 |
| **可组合性** | M | 生成的 `New*Handler` 的 `Deps` 接口缺少 `Dep` 前缀的 getter——生成的代码无法直接 `sso.WithHandler` |

#### 架构设计

**修复策略（按优先级）：**

| 优先级 | 修复项 | 模板文件 | 行数估算 |
|--------|--------|---------|---------|
| P0 | Authenticator 模板：`Authenticate()` 返回 `nil, core.ErrUserNotFound` 而非 `nil, fmt.Errorf(...)` | `templates.go:55` | 1 行 |
| P0 | Store 模板：取消注释 CRUD 方法，生成 `return fmt.Errorf("not implemented")` | `templates.go:164-241` | 10 行 |
| P0 | Handler 模板：`handleGet` 返回 HTTP 404 而非 200 + `"not implemented"` | `templates_handler.go:56-73` | 2 行 |
| P1 | Handler 模板：生成完整的 `Deps` 接口签名（所有依赖 getter） | `templates_handler.go:24` | 5 行 |
| P1 | Grant 模板：`HandleToken` 返回正确的 grant 错误码而非 `not implemented` | `templates_handler.go:260` | 1 行 |
| P2 | 所有模板：添加 `// After filling in your logic, remove this marker.` 注释 | 多处 | 6 行 |

**生成的代码质量提升示例（Authenticator）：**

```go
// 当前（错误）：返回 fmt.Errorf，编译通过但运行时不可用
func (a *{{.Name}}Authenticator) Authenticate(ctx context.Context, req *core.AuthRequest) (*sso.AuthResult, error) {
    return nil, fmt.Errorf("{{.LowerName}} not implemented")
}

// 修复后（正确）：返回正确的 sentinel，集成测试可正确识别"用户不存在"
func (a *{{.Name}}Authenticator) Authenticate(ctx context.Context, req *core.AuthRequest) (*sso.AuthResult, error) {
    return nil, core.ErrUserNotFound  // 替换为你的身份验证逻辑
}
```

#### 对现有系统的影响

| 影响项 | 程度 |
|--------|------|
| 模板代码变更 | ~30 行（填充 TODO + 修复哨兵值） |
| 编译检查 | 不变——代码已可编译 |
| 运行时行为 | 从不正确（总是 nil, error）变为更明显（nil, sentinel + user-friendly 占位消息） |
| 向后兼容 | 向后兼容——生成的代码 API 签名不变 |

---

### 2.5 方向五：HTTP/2 配置化（P2）

#### 为什么需要（技术价值）

| 价值 | 说明 |
|------|------|
| **部署场景适应** | 非反向代理部署场景（设备直连、边缘节点、APNs HTTP/2 push）需要 HTTP/2 |
| **gRPC 支持** | gRPC 需要 HTTP/2——如果用户想用 sso-server 内建 gRPC 服务（目前通过 `grpcserver/`） |
| **运维可控** | 硬编码环境变量 override 不在 `config.yaml` 中可见，运维可能不知情 |
| **审计合规** | 配置审计应能报告 HTTP/2 启用/禁用状态 |

#### 核心挑战

| 挑战 | 难度 | 说明 |
|------|------|------|
| **位置选择** | L | `ServerConfig` 需要 `http2` 字段——默认 `nil`（保持当前行为：禁用） |
| **与 GODEBUG 共存** | L | 如果用户显式设置了 `GODEBUG=http2server=1`，配置应尊重用户的显式设置优先 |
| **文档更新** | L | 需要在配置参考文档中记录此字段 |

#### 架构设计

```go
// config/config_server.go

// ServerConfig 包含服务器配置。
type ServerConfig struct {
    // ... 现有字段 ...

    // HTTP2 控制 HTTP/2 服务器端支持。
    // nil = 禁用 HTTP/2（当前默认行为——通过设置 GODEBUG=http2server=0）。
    // 当设置为 &HTTP2Config{Enabled: true} 时，HTTP/2 被启用。
    // 注意：如果环境变量 GODEBUG 已被显式设置，此字段不覆写（显式环境变量优先）。
    HTTP2 *HTTP2Config `yaml:"http2,omitempty"`
}

type HTTP2Config struct {
    // Enabled 启用 HTTP/2 服务器端支持。
    Enabled bool `yaml:"enabled"`
}
```

**接线逻辑（`main_helpers.go`）：**

```go
// 从 config 读取 http2 配置
if cfg.Server.HTTP2 == nil || !cfg.Server.HTTP2.Enabled {
    // 默认禁用——只在 GODEBUG 未设置时设置
    if os.Getenv("GODEBUG") == "" {
        os.Setenv("GODEBUG", "http2server=0")
    }
}
// 如果 cfg.Server.HTTP2.Enabled == true，不设置 GODEBUG——HTTP/2 保持默认启用
```

#### 对现有系统的影响

| 影响项 | 程度 |
|--------|------|
| 配置变更 | `ServerConfig` 新增 2 个字段（`HTTP2Config` 结构体） |
| 接线变更 | `main_helpers.go` 约 5 行修改 |
| 向后兼容 | 完全兼容——`nil` = 当前行为（禁用） |
| 文档变更 | 更新 `docs/config-reference.md` |

---

## 3. 接口设计建议

### 3.1 通用原则

| 原则 | 说明 |
|------|------|
| **后端不变准则** | 方向一（i18n）、方向二（信任设备）、方向五（HTTP/2）不需要后端 SPI 变更——仅前端或配置变更 |
| **渐进式 API 扩展** | 方向三（批量管理）使用新端点而非修改现有端点——不破坏 Admin SPA 现有功能 |
| **默认向后兼容** | 所有新配置字段的零值等于当前行为 |
| **SPA 自包含** | 方向一（i18n）的翻译数据嵌入 SPA 而非依赖后端 API |

### 3.2 各方向接口映射

| 方向 | 新接口/数据类型 | 所属层 | 类型 |
|------|---------------|--------|------|
| ① i18n | `i18n.js`（轻量引擎）+ `i18n.*.json`（翻译文件） | `interfaces/web/*/` | 前端 JS |
| ② 信任设备 | 无新接口——复用现有 `POST /auth/login?trust_device` + `/me/devices*` | 前端 | 无 |
| ③ 批量管理 | `POST /admin/*/batch`、`GET /admin/*/export`、`BatchJobStore` SPI | `interfaces/admin/` + `shared/core/` | REST + SPI |
| ④ 代码生成器 | 无新接口——修复现有模板 | `cmd/sso-ctl/generate/` | Go 模板 |
| ⑤ HTTP/2 | `config.HTTP2Config` | `config/` | 配置结构体 |

### 3.3 批量操作 API 设计

**原则：** 批量操作是幂等操作的可组合调用，不是特殊资源。

```go
// BatchJobStore 管理异步批量作业的状态。
// 实现：memory（单节点测试）+ sqlite（生产持久化）
type BatchJobStore interface {
    // CreateJob 创建一个批量作业并返回其 ID。
    CreateJob(ctx context.Context, job *BatchJob) error
    
    // GetJob 返回作业的当前状态。
    GetJob(ctx context.Context, jobID string) (*BatchJob, error)
    
    // UpdateJobProgress 更新作业进度（由 worker goroutine 调用）。
    UpdateJobProgress(ctx context.Context, jobID string, processed int) error
    
    // SetJobFailed 将作业标记为失败并记录错误。
    SetJobFailed(ctx context.Context, jobID string, errors []BatchError) error
    
    // ListJobs 返回租户的最近作业列表（含分页）。
    ListJobs(ctx context.Context, tenantID string, limit, offset int) ([]*BatchJob, error)
}

type BatchJob struct {
    ID          string       `json:"id"`
    Type        string       `json:"type"`        // "user_import" | "user_delete" | "audit_export"
    TenantID    string       `json:"tenant_id"`
    Status      BatchStatus  `json:"status"`
    Total       int          `json:"total"`
    Processed   int          `json:"processed"`
    Errors      []BatchError `json:"errors,omitempty"`
    CreatedBy   string       `json:"created_by"`
    CreatedAt   time.Time    `json:"created_at"`
    CompletedAt *time.Time   `json:"completed_at,omitempty"`
}
```

**关键设计决策：** `BatchJobStore` 放在 `shared/core/` 还是 `domains/admin/`？

| 选项 | 优势 | 劣势 |
|------|------|------|
| **A: `shared/core/`** | 与 `SessionStore`、`ClientStore` 等核心 SPI 平级；跨模块可复用 | `core/` 已较大（建议分割前检查文件大小） |
| **B: `domains/admin/`** | 域边界清晰——批量操作是 admin 域的概念 | 新增 package；`interfaces/admin/` 会导入 `domains/admin/` |

**推荐：选项 B**——批量操作是管理控制台特有的概念，不应提升到核心 SPI 层。

---

## 4. 技术选型

### 4.1 引入新技术栈的决策

| 方向 | 建议 | 理由 |
|------|------|------|
| ① SPA i18n | **自建**轻量 JS i18n 引擎（~50 行） | 零外部依赖；4 个 SPA 都是 Vanilla JS，不需引入 react-intl/vue-i18n |
| ② 信任设备 UX | **零**新技术 | 纯前端变更，复用后端现有 API |
| ③ 批量管理 | **引入** `BatchJobStore` SPI + memory 实现 | 新 SPI 但模式与现有 SPI 一致（接口 + memory impl） |
| ④ 代码生成器 | **零**新技术 | 修复现有模板，不改变生成器架构 |
| ⑤ HTTP/2 | **零**新技术 | 仅配置结构体 + 接线逻辑 |

**结论：所有五个方向均不需要引入新的第三方依赖或技术栈。**

### 4.2 自建 vs 采购决策

| 决策项 | 建议 | 理由 |
|--------|------|------|
| i18n 翻译文件管理 | 自建 | 4 个 SPA 的翻译 key 总数约 50-100 条/SPA——不需要 Lokalise/Crowdin 等 TMS。初期用 JSON 文件 + git 管理 |
| CSV 导入解析 | 自建 | Admin SPA 的 CSV 解析可以手写（不需要 Papa Parse 等库）——输入格式可控，不需要复杂的转义/编码检测 |
| 批量作业调度 | 自建 | 不需要 Celery/Redis Queue——SSO 的批量操作是低频（每天几次）、小规模（<10,000 条） |

### 4.3 不做之事

| 不做 | 原因 |
|------|------|
| 不引入前端框架（React/Vue/Svelte） | 4 个 SPA 共 2892 行（全部 Vanilla JS），引入框架会增加构建工具链和开发者学习成本 |
| 不引入国际化框架（react-intl/vue-i18n/FormatJS） | 轻量自建 ~50 行即可满足需求——不需要 ICU 消息格式、复数处理、上下文选择器 |
| 不做翻译管理系统集成 | 初期翻译量小，JSON 文件 + git 协作已足够 |
| 不将 SPA 迁移为 SSR（服务器端渲染） | 当前 SPA 架构工作良好，SSR 会增加服务器负载和架构复杂度 |
| 不引入 WebSocket 做批量作业进度推送 | 轮询（`GET /admin/batch-jobs/{id}` 每 2s）足够——批量操作不需要实时推送 |

---

## 5. 实施路线图

### 5.1 优先级总览

```
        高 │ 方向② 信任设备 UX               方向① SPA i18n
           │     P0 ───── 后端就绪，仅需 UI        P0 ───── 市场准入
           │
   用户价值 │ 方向③ Admin 批量管理
           │     P1 ───── 企业采购准入
           │
        低 │ 方向④ 代码生成器修复         方向⑤ HTTP/2 配置化
           │     P2 ───── 开发者体验               P2 ───── 部署灵活性
           │
           └──────────────────────────────────────────────
              低                        高
                      实现复杂度
```

### 5.2 阶段划分

#### 阶段一：速赢——信任设备 UX + HTTP/2（1 周）

| 子项 | 工作量 | 产出 |
|------|--------|------|
| Login SPA 添加"信任此设备"复选框 | S（~30 行） | MFA 跳过流程在前端可用 |
| Portal SPA 添加设备管理面板 | S（~100 行） | 用户可查看/撤销信任设备 |
| `ServerConfig.HTTP2` 配置字段 | XS（~30 行） | HTTP/2 可在 config.yaml 中控制 |

**验证标准：** 用户登录时勾选"信任此设备"→ 后续 30 天内相同设备上跳过 MFA。Portal 中可看到信任设备列表并撤销。`config.yaml` 中设置 `http2.enabled: true` 后 sso-server 使用 HTTP/2。

#### 阶段二：核心——SPA i18n（2-3 周）

| 子项 | 工作量 | 产出 |
|------|--------|------|
| `i18n.js` 轻量引擎编写 | S（~50 行） | 可复用的翻译引擎 |
| Login SPA 消息外化 | M（~100 行） | 全部用户可见字符串 → key |
| Admin SPA 消息外化 | L（~200 行） | 同上 |
| Portal SPA 消息外化 | M（~80 行） | 同上 |
| Developer SPA 消息外化 | S（~40 行） | 同上 |
| `en.json` 翻译 key 提取 | S | 将所有硬编码字符串提取为 key |
| `es.json` 版本 1 翻译 | S | 西班牙语第一版翻译 |

**验证标准：** 4 个 SPA 全部使用 `t()` 函数输出字符串。浏览器设置 `Accept-Language: es` → 所有 SPA 显示西班牙语。未翻译的语言回退到英语。

#### 阶段三：企业——Admin 批量管理（3-4 周）

| 子项 | 工作量 | 产出 |
|------|--------|------|
| `BatchJobStore` SPI + memory impl | M | 批量作业状态管理 |
| `POST /admin/users/batch` 批量创建 | M | 批量用户导入 API |
| `POST /admin/users/batch/delete` 批量删除 | M | 批量用户删除 API |
| `GET /admin/users/export` CSV 导出 | M | 用户列表导出 |
| `GET /admin/audit/export` 审计导出 | M | 审计日志导出 |
| `?q=` 搜索参数（users/clients/tenants） | M | 搜索能力 |
| Admin SPA 批量选择 UI | M | 前端批量操作界面 |
| Admin SPA CSV 导入 UI | M | 拖拽上传 + 预览 + 错误报告 |

**验证标准：** 管理员可在 Admin SPA 中：搜索用户 → 批量选择 → 删除。上传 CSV 文件 → 预览前 5 行 → 确认导入 → 看到进度条和错误报告。审计日志可导出为 CSV。

#### 阶段四：工具——代码生成器修复（1 周）

| 子项 | 工作量 | 产出 |
|------|--------|------|
| 修复 4 个模板的哨兵值（ErrUserNotFound / 404 / 正确错误码） | S | 生成的代码运行时行为正确 |
| 恢复 Store 模板的 CRUD 方法（从注释中恢复） | S | 完整的 Store 骨架 |
| 修复 Handler 模板的 Deps 接口 | S | 生成可 `sso.WithHandler` 的代码 |
| `sso-ctl generate --help` 更新 | XS | 文档同步 |

**验证标准：** `sso-ctl generate authenticator myauth` → `go build ./...` 通过 → 生成的 Authenticator 返回正确的 sentinel（`ErrUserNotFound`）。`sso-ctl generate handler myresource` → 生成代码可直接注册到路由器。

### 5.3 依赖关系图

```
阶段一（速赢）
├── 方向② 信任设备 UX    ← 无前置依赖
├── 方向⑤ HTTP/2          ← 无前置依赖
│
阶段二（核心）
├── 方向① SPA i18n        ← 无前置依赖（但需 SPA 目录结构了解）
│
阶段三（企业）
├── 方向③ 批量管理        ← 依赖阶段一的信任设备吗？不依赖
│                          ← 依赖后端 Admin API（已存在）
│
阶段四（工具）
├── 方向④ 代码生成器      ← 无前置依赖
```

**推荐启动顺序：** 阶段一（速赢）→ 阶段二（并行于阶段三）→ 阶段三（企业）→ 阶段四（工具）

阶段一和阶段二可并行进行（不同开发者/技能栈可同时工作）。阶段三和阶段四也可并行。

### 5.4 风险与缓解

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| SPA i18n 翻译 key 数量级超出预期（Admin SPA 1385 行，可能有 100+ UI 字符串） | M | M | 优先外化面向用户的字符串（按钮、标签、错误消息），管理面内部标签可延迟 |
| 批量管理 API 的后端搜索支持工作量较大（users/clients/tenants 需要每个 store 实现搜索） | M | M | 搜索实现可分阶段：阶段一只实现基本前缀搜索，阶段二再加全文搜索 |
| 信任设备复选框的 UX 设计选择增加 scope creep | L | L | 初始实现简单的 checkbox + "Trust this device for 30 days"硬编码文案，不做自定义过期时间下拉框 |
| 代码生成器修复后兼容性（已有用户依赖 TODO 占位的代码生成） | L | L | 不改变生成的代码 API 签名——哨兵值从 `fmt.Errorf` 改为 `core.ErrUserNotFound` 是运行时行为变化但编译兼容 |
| i18n 翻译质量（ES 机翻 vs 专业翻译） | M | L | V1 使用机器翻译 + `# TODO: Review translation` 注释标注；发布前通知社区/客户审校 |

### 5.5 与前置分析的关系

这一分析的五方向完全独立于前置分析（`docs/architect-analysis-v6-five-directions.md`）的五方向：

| 前置分析方向 | 本分析方向 | 关系 |
|-------------|-----------|------|
| 多区域复制（P0） | SPA i18n（P0） | **独立**——一个是后端基础设施，一个是前端 |
| 外部依赖韧性（P1） | 信任设备 UX（P0） | **独立** |
| 限流完备化（P1） | Admin 批量管理（P1） | **独立** |
| 配置验证（P2） | 代码生成器（P2） | **独立** |
| 令牌溯源（P2） | HTTP/2 配置（P2） | **独立** |

两个分析共 10 个方向，无重叠，互不阻塞，可并行实施。

---

## 6. 总结

| 维度 | 评估 |
|------|------|
| **架构健康度** | 很高——所有五个方向都可以在当前架构内修复，不需要架构重组 |
| **投入产出比最高** | 方向②（信任设备 UX）——后端已 100% 就绪，仅需~130 行前端代码 |
| **业务价值最高** | 方向①（SPA i18n）——全球部署的身份平台必须支持多语言 |
| **企业采购准入门槛** | 方向③（Admin 批量管理） |
| **开发者体验价值** | 方向④（代码生成器修复） |
| **部署灵活性** | 方向⑤（HTTP/2 配置化） |
| **不做之事** | 五个方向均不需要新第三方依赖、新前端框架、新构建工具 |

### 核心建议

1. **立即启动方向②**——后端投资已沉没，~130 行前端代码就能产生可用功能
2. **方向①的 i18n 不要过度设计**——轻量 JS 引擎 + JSON 翻译文件就够，不要引入 react-intl/vue-i18n
3. **方向③的批量操作异步化是正确选择**——不要为了"简单"而同步实现（10,000 用户导入不应阻塞管理线程）
4. **方向④的修复聚焦行为正确性**——哨兵值（sentinel）的正确性比填充 TODO 更重要
5. **方向⑤是运维最佳实践**——任何硬编码的环境变量覆写最终都应该配置化
