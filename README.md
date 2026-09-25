# 许可证依赖冲突审计台

基于 **FastAPI + SQLite** 的依赖许可证合规审计工具。上传包含包名、版本、许可证及依赖边的
manifest（或直接上传 **CycloneDX JSON** SBOM），系统会：

1. **规范化节点** —— 统一包名/版本写法、把许可证别名（`Apache 2.0`、`GPLv3`、`MIT License`…）
   映射为规范 SPDX 标识，合并重复节点并归一依赖边；
2. **计算传递约束** —— 按内置许可证兼容矩阵（宽松型 / 弱 copyleft / 强 copyleft / 专有），
   对依赖图做传递可达性分析，记录每个节点受到的来自所有祖先的许可证约束；
3. **标出最短冲突路径** —— 对每一对不兼容的“祖先许可证 → 后代许可证”，用 BFS 给出
   **最短依赖路径**（冲突路径上每个节点都标注许可证），硬冲突与“需人工确认”告警分级展示；
4. **按包筛选** —— 包名子串过滤，凡最短路径经过该包的冲突都会保留；
5. **导出 JSON** —— 完整审计结果（含筛选结果）可一键下载；审计记录持久化在 SQLite；
6. **两次审计对比** —— 从历史中选择两个 `audit_id`，按 **包名+版本** 配对节点、
   按「祖先节点 → 被依赖节点」配对冲突/告警，展示新增、消失及状态变化（严重程度/
   许可证/最短路径），每条都附上双方各自的最短依赖路径；对比为纯只读操作，
   记录不存在时返回明确错误（404），**不会写入新审计**；
7. **跨审计复核标记** —— 对冲突/告警条目按「祖先节点 + 被依赖节点 + 双方规范化许可证」
   生成指纹，在网页上填写复核备注与失效时间即可打标，也可随时撤销；标记持久化在 SQLite，
   对**所有历史审计**生效：读取任意审计时，指纹一致且未过期、未撤销的最新标记会自动
   附到对应条目上，并区分「待复核 / 已复核」。许可证变更（指纹改变）、标记过期或被撤销后，
   条目自动回到待复核；原始冲突、严重程度与两次审计对比结果完全不受影响；
8. **CycloneDX SBOM 导入** —— 网页粘贴/上传与 `POST /api/audit`、`/api/audit/upload`
   均自动识别 CycloneDX JSON（`bomFormat` + `components` + `dependencies`）：
   组件的 `bom-ref` 映射为包节点，按 `ref` / `dependsOn` 还原依赖边后复用同一套
   兼容矩阵与最短路径冲突分析；审计结果照常进入历史列表并可导出；
9. **根包退役预演** —— 根包即**没有入边的包**（没有任何其他包依赖它）。在网页第 3 节
   选择一条已保存审计并勾选一个或多个根包（或调用
   `GET /api/audits/{id}/retire?retire=…`），服务端沿 使用方 → 被依赖方 的边从
   剩余根包重算可达集合，展示因退役失去可达性的包、仍被其他根包共用的包，
   以及随失联包消失的许可证冲突（附原最短路径）；预演为纯只读操作，
   **不创建审计、不改动复核标记**，原生 manifest 与 CycloneDX 审计均可使用，
   可反复调整选择；
10. **单包许可证替换预演** —— 在网页第 4 节选择一条已保存审计、一个包和候选
    SPDX 许可证（或调用 `GET /api/audits/{id}/relicense?package=…&license=…`），
    服务端**仅替换该节点的许可证**，沿原依赖图（节点与依赖边不变）重算传递兼容判定
    与最短冲突路径，并按「祖先包 → 被依赖包」配对原结果与预演结果：新增、消失及
    等级变化的冲突都附上两侧的最短依赖路径，同时给出硬冲突数、告警数与冲突总数的
    净变化；包不存在或候选许可证不在内置矩阵时返回明确错误（422）；预演为纯只读操作，
    **不创建审计、不改动复核标记**，原生 manifest 与 CycloneDX 审计均可使用；
11. **未解析依赖补边预演** —— 在网页第 5 节选择一条已保存审计后，页面列出该审计
    **源包仍存在**的未解析依赖引用；选一条引用和一个现有目标包（或调用
    `GET /api/audits/{id}/edgefix?source=…&reference=…&target=…`），服务端只在内存中
    补一条 **使用方 → 被依赖方** 的边并移除该未解析项（其余节点、许可证与边完全不变），
    重算传递约束与最短冲突路径，并按「祖先包 → 被依赖包」配对原结果与预演结果：
    展示新增及最短路径变化的冲突（附两侧路径）、剩余未解析项与冲突数净变化；
    引用或目标无效、补成自依赖或重复边返回明确错误（422）；预演为纯只读操作，
    **不创建审计、不改动复核标记**，原生 manifest 与 CycloneDX 审计均可使用。
12. **最少断边分析** —— 在网页第 8 节选定一条已保存审计中的冲突或告警后（或调用
    `GET /api/audits/{id}/edgecut/{conflict_id}`），沿审计保存的现有
    **使用方 → 被依赖方** 图，计算要让该条冲突的祖先包无法再到达被依赖包所需删除的
    **最少依赖边**（有向图 s-t 最小边割：单位容量 Edmonds-Karp 最大流 = 最小割）：
    返回一组**确定性**的建议断边集合与数量，并给出同等数量的「边不相交」见证路径
    （并行路径、汇合路径与依赖环都纳入计算，不只处理当前最短路径）；
    网页展示原最短路径、建议断边（标出落在原最短路径上的边）与断边后是否仍可达。
    审计或冲突/告警不存在时返回明确错误（404）；分析为纯只读操作，
    **不改动原审计结果与复核标记**，原生 manifest 与 CycloneDX 审计均可使用；
13. **全图许可证选定** —— 在网页第 6 节选择一条已保存审计后（或调用
    `GET /api/audits/{id}/license-select`），服务端对**每个包**从其现有
    **OR 表达式 / 并列条目候选**中固定选定一个许可证（只声明一个许可证的包
    视为固定），沿 **使用方 → 被依赖方** 的**全部可达关系**（含传递关系，
    非仅直接边）逐条调用现有兼容矩阵，用确定性回溯搜索（MRV + 分支限界）
    求一份全图一致的选择：
    - 存在**所有关系均兼容**的方案 → 结论「全图可行」，返回每包选择；
    - 无法全兼容但能**避开全部硬冲突** → 标为「**需人工确认**」，列出最终选择下
      仍为矩阵 warning 的告警关系（附最短可达路径）；
    - **任何选择都含硬冲突** → 给出「**无解**」结论，同时返回硬冲突最少的
      确定性选择与硬冲突关系清单；
    - **未知许可证包**或**未解析依赖**一律明确标为「**未判定**」（包级与关系级
      分别列出），已知许可证子图仍给出判定，但**不能声称全图可行**；
      若已知子图本身无解（硬冲突不会因日后补全而消失），整体仍判无解。

    页面展示结论徽标、兼容/告警/硬冲突/未判定关系统计、每包选定的许可证与候选、
    三类关系清单及各自的最短可达路径。分析为纯只读操作，**不创建审计、不改动原审计
    结果与复核标记**，原生 manifest 与 CycloneDX 审计均可使用；
14. **审计复现包（可离线转交）** —— 在网页第 2 节选择一条历史审计即可下载复现包
    （或调用 `GET /api/audits/{id}/repro`）：从 SQLite 取出**原始 manifest** 与
    **未附着实时复核标记的保存结果**，导出含格式版本（`audit-repro/v1`）、审计名称
    及两者 **SHA-256 摘要**的单个 JSON 文件，可离线转交。上传该包核验
    （网页第 2 节「上传核验」，或 `POST /api/repro/verify` / `/api/repro/verify/upload`）时，
    服务端按**稳定键序列化**重算两处摘要，再用包内 manifest 调用现有分析器，
    剔除审计 ID、时间等运行元数据后逐项比对节点、依赖边、冲突严重程度与最短路径，
    并指出**首个不一致字段**；只有摘要与复算结果**都一致**才判通过。
    核验为纯只读操作（不创建审计、不改动复核标记），格式错误返回明确的 422 提示。

## 多许可证候选（OR）组合判定

当一个包声明了**多个可选许可证**（SPDX 的 OR 选择语义）时，工具不再把整个表达式
当作无法识别的未知许可证，而是解析为**候选集合**逐一判定：

- **原生 manifest**：`license` 支持字符串或数组——形如 `"MIT OR GPL-2.0"` 的纯 OR
  表达式，或 `["MIT", "Apache-2.0"]` / `[{"id": "MIT"}, …]` 这样的**多个并列条目**，
  都解析为候选（条目按声明顺序去重）；
- **CycloneDX 组件**：`licenses` 中的 SPDX `id` / `expression` / `license.name`
  同样处理——纯 ` OR ` 表达式与多个并列许可证条目都成为候选；
- **组合判定**：祖先与依赖各有候选时，对每个 `(祖先候选, 依赖候选)` 组合逐一调用
  现有兼容矩阵；**全部组合冲突才报硬冲突、全部兼容才判通过（不列出条目）**，
  其余（存在可兼容组合但并非全部兼容，或组合中含需人工确认项）报**需人工确认**。
  冲突/告警卡片可折叠展示**每个候选组合的判定（兼容/冲突/需人工确认）与矩阵逐条理由**，
  并保留原**最短依赖路径**与跳数；汇总信息给出总组合数及三类计数；
- **仍按未知处理的情况**：表达式含 `AND`、括号（如 `(MIT OR ISC)`）、`WITH` 或
  任何矩阵外未知标识（如 `MIT OR OFL-1.1`），以及并列条目中混入未知许可证时，
  不做候选拆分，整体保留原文标记为 unknown，相关边按“需人工确认”告警处理；
- **单许可证语义不变**：只有一个许可证时结果结构与判定原因与旧版本完全一致
  （冲突条目不带组合明细字段）。多候选节点的 `license_category` 为 `multi`，
  节点额外携带 `license_candidates` / `license_tokens` / `license_multi` 字段。

快速示例（祖先 `GPL-2.0 OR MIT`、依赖 `Apache-2.0`）：两个组合中
`GPL-2.0→Apache-2.0` 冲突、`MIT→Apache-2.0` 兼容，因此整体**不报硬冲突**，
判为「需人工确认」并列出两个组合的判定与原最短路径：

```json
{
  "severity": "warning",
  "ancestor": "app@1.0.0", "node": "lib@1.0.0",
  "ancestor_license": "GPL-2.0 OR MIT", "node_license": "Apache-2.0",
  "ancestor_multi": true, "node_multi": false,
  "distance": 1, "path": ["app@1.0.0", "lib@1.0.0"],
  "combination_counts": {"total": 2, "ok": 1, "conflict": 1, "warning": 0},
  "candidate_combinations": [
    {"parent": "GPL-2.0", "dep": "Apache-2.0", "status": "conflict",
     "reason": "GPL-2.0 与 Apache-2.0 专利条款冲突，不能组合进同一作品。"},
    {"parent": "MIT", "dep": "Apache-2.0", "status": "ok",
     "reason": "宽松许可证对集成依赖无 copyleft 约束。"}
  ]
}
```

## 快速开始（Docker Compose，一键启动，推荐）

```bash
docker compose up --build          # 前台启动（加 -d 可后台运行）
```

服务监听容器内 **8000** 端口，Compose 已映射到宿主机 **8000**：网页界面与 JSON API
共用该端口——浏览器打开 <http://localhost:8000/> 即可使用网页，API 则通过
`http://localhost:8000/api/...` 访问（交互式文档在 <http://localhost:8000/docs>）。
容器启动时会自动初始化数据库（SQLite 文件位于卷 `audit-data`，容器内路径 `/data/audit.db`）。

启动后访问（均为宿主机 8000 端口）：

| 地址 | 说明 |
| --- | --- |
| <http://localhost:8000/> | 网页界面（已自动载入示例 manifest，可一键切换 CycloneDX 示例；第 2 节可对比两次历史审计、下载/上传核验审计复现包，第 3 节可做根包退役预演，第 4 节可做单包许可证替换预演，第 5 节可做未解析依赖补边预演，第 6 节可做全图许可证选定，第 8 节可对单条冲突做最少断边分析） |
| <http://localhost:8000/docs> | Swagger 风格交互式 JSON API 文档 |
| <http://localhost:8000/redoc> | ReDoc API 文档 |
| <http://localhost:8000/api/matrix> | 许可证兼容矩阵（机器可读） |
| <http://localhost:8000/healthz> | 健康检查 |

停止并保留数据：`docker compose down`；连同数据卷一起清除：`docker compose down -v`。
8000 端口被占用时，可修改 `docker-compose.yml` 中 `"8000:8000"` 的宿主机一侧
（例如 `"18000:8000"`），随后访问 <http://localhost:18000/>。

## 本地直接运行

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

数据库默认创建在 `./data/audit.db`，可用环境变量覆盖：

- `DATA_DIR` —— 数据库目录（默认 `./data`）；
- `DATABASE_URL` —— 直接指定 SQLite 文件路径（如 `/var/lib/audit/audit.db`）。

## manifest 格式

```json
{
  "name": "my-app",
  "packages": [
    {
      "name": "web-app",
      "version": "1.0.0",
      "license": "AGPL-3.0",
      "dependencies": [
        "billing-core@1.2.0",
        { "name": "ui-kit", "version": "^0.9.0" },
        { "name": "font-pack", "version": "2.0.0", "license": "MIT" }
      ]
    },
    { "name": "billing-core", "version": "1.2.0", "license": "GPL-2.0" }
  ],
  "dependencies": {
    "billing-core@1.2.0": ["font-pack@2.0.0"]
  },
  "edges": [
    { "source": "web-app@1.0.0", "target": "billing-core@1.2.0" }
  ]
}
```

约定：

- `packages` 声明节点；`dependencies`（包内或顶层，数组或 `名字: 版本` 映射均可）与
  `edges` 声明依赖边，方向为 **使用方 → 被依赖方**，传递约束沿边传播；
- 只给包名不给版本时，若 `packages` 中该名字唯一则自动解析，多个版本需用 `name@version` 消歧；
- 无法解析到已声明节点的依赖会进入 `unresolved` 列表并产生告警，不会凭空造节点；
- 许可证字段支持字符串或数组：`"MIT OR GPL-2.0"` 这类纯 OR 表达式与
  `["MIT", "Apache-2.0"]` 这类多个并列条目都按**多许可证候选**处理（详见
  「多许可证候选（OR）组合判定」）；未在矩阵中识别的许可证（如 `OFL-1.1`），
  以及含 `AND`、括号或未知标识的表达式，保留原文并标记为 unknown，
  相关边按“需人工确认”告警处理，而非误判为兼容；
- 依赖环会被安全处理（BFS 节点只访问一次），不影响最短路径计算。

## CycloneDX JSON（SBOM）导入

除上述原生 manifest 外，网页粘贴/上传与 `POST /api/audit`、`/api/audit/upload`
均可直接接受 **CycloneDX JSON**。识别规则（满足其一）：

- 顶层存在 `bomFormat` 字段（取值必须为 `CycloneDX`，其他取值返回 422）；
- 或顶层存在数组形式的 `components` 且未使用原生格式的 `packages`。

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": { "component": { "type": "application", "name": "shop-backend", "version": "3.2.0" } },
  "components": [
    {
      "type": "application",
      "bom-ref": "pkg:app/shop-backend@3.2.0",
      "name": "shop-backend",
      "version": "3.2.0",
      "licenses": [ { "license": { "id": "GPL-2.0" } } ]
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/web-ui@1.4.2",
      "name": "web-ui",
      "version": "1.4.2",
      "licenses": [ { "expression": "Apache-2.0" } ]
    }
  ],
  "dependencies": [
    { "ref": "pkg:app/shop-backend@3.2.0", "dependsOn": ["pkg:npm/web-ui@1.4.2"] }
  ]
}
```

导入约定：

- **节点**：每个 `components[]` 组件按 `name` + `version` 规范化为包节点（与原生
  manifest 同一套规则），组件的 `bom-ref` 记录在节点的 `bom_refs` 字段并建立
  `bom-ref → 节点` 映射；审计名依次取顶层 `name`、`metadata.component.name`、
  请求参数 `name`；
- **依赖边**：`dependencies[]` 按 `ref` / `dependsOn` 还原为「使用方 → 被依赖方」
  的依赖边，随后复用同一套兼容矩阵与最短路径冲突分析；
- **许可证**：取组件 `licenses` 中的 SPDX `id` 或 `expression`（兜底取
  `license.name`，同样走别名规范化）；纯 ` OR ` 表达式（如
  `{"expression": "MIT OR Apache-2.0"}`）与多个并列 id/name 条目都解析为
  **多许可证候选**（候选集合相同时视为同一许可证，允许合并）；含 `AND`、
  括号或未知标识的表达式保留原文按未知处理；**缺失许可证按未知处理**
  （显示为 `UNLICENSED`，相关边按“需人工确认”告警）；
- **422（不静默合并）**：同一 `bom-ref` 重复出现，或同名同版本组件对应不同许可证
  （单许可证按规范化标识比较，多候选按去重后的候选集合比较，`MIT` 与
  `MIT License` 视为相同）时，返回明确的 `422` 错误并中止导入，需修正 BOM
  后重新提交；
- **未解析引用**：`dependencies` 中引用了不存在于 `components` 的 bom-ref 时，
  对应条目进入 `unresolved` 列表并产生告警，不会凭空造节点；
- 结果与原生 manifest 完全一致地进入历史列表、参与两次审计对比、按包筛选与导出，
  导出 JSON 中带 `"source_format": "cyclonedx"` 标识。

内置示例：`GET /api/sample/cyclonedx`（网页端「载入 CycloneDX 示例」按钮同源）。

```bash
# 直接提交 CycloneDX BOM 审计
curl -X POST http://localhost:8000/api/audit \
  -H "Content-Type: application/json" \
  -d "{\"manifest\": $(cat static/examples/sample-cyclonedx.json)}"

# 或上传 SBOM 文件
curl -F "file=@static/examples/sample-cyclonedx.json" http://localhost:8000/api/audit/upload

# 422 示例：重复 bom-ref
$ curl -s -X POST http://localhost:8000/api/audit -H "Content-Type: application/json" \
    -d '{"manifest": {"bomFormat": "CycloneDX", "components": [
          {"bom-ref": "a", "name": "x", "version": "1"},
          {"bom-ref": "a", "name": "y", "version": "2"}]}}'
{"detail":"components 中 bom-ref 重复：'a'。为避免静默合并组件，已中止导入，请去重后重新提交。"}
```

## JSON API 速览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/audit` | 提交 JSON：`{"manifest": {...}, "name": "可选名称"}`（自动识别 CycloneDX BOM） |
| POST | `/api/audit/upload` | 上传 `.json` manifest / CycloneDX SBOM 文件（multipart） |
| GET | `/api/audits?limit=20` | 历史审计列表 |
| GET | `/api/audits/{id}` | 获取审计结果；`?package=xxx` 按包筛选 |
| GET | `/api/audits/{id}?download=true&package=xxx` | 导出（筛选后的）JSON 文件 |
| GET | `/api/audits/compare/{base_id}/{target_id}` | **两次审计对比**（只读，不写入） |
| GET | `/api/audits/{id}/retire?retire=a@1&retire=b@2` | **根包退役预演**（只读；不带参数返回根包列表） |
| GET | `/api/audits/{id}/relicense?package=a@1&license=MIT` | **单包许可证替换预演**（只读；不带参数返回可选包与候选许可证列表） |
| GET | `/api/audits/{id}/edgefix?source=a@1&reference=x@2&target=x@1` | **未解析依赖补边预演**（只读；不带参数返回源包仍存在的未解析引用与目标包列表） |
| GET | `/api/audits/{id}/edgecut/{conflict_id}` | **最少断边分析**（只读；返回让祖先包无法再到达被依赖包的确定性最少断边集合） |
| GET | `/api/audits/{id}/license-select` | **全图许可证选定**（只读；每包从现有 OR/并列候选固定选一个，按全部可达关系求全图一致选择） |
| GET | `/api/audits/{id}/repro` | **导出审计复现包**（原始 manifest + 保存结果 + 两者 SHA-256 摘要，可离线转交） |
| POST | `/api/repro/verify` | **核验复现包**（JSON 请求体，只读：重算摘要 + 分析器复算逐项比对） |
| POST | `/api/repro/verify/upload` | **上传复现包文件核验**（multipart，只读，不创建审计） |
| DELETE | `/api/audits/{id}` | 删除审计记录（不影响复核标记） |
| POST | `/api/reviews` | **创建复核标记**（按审计中的冲突条目，跨审计生效） |
| GET | `/api/reviews?state=active&fingerprint=…` | 复核标记记录列表（可按状态/指纹筛选） |
| GET | `/api/reviews/{id}` | 获取单条复核标记记录 |
| POST | `/api/reviews/{id}/revoke` | **撤销复核标记**（保留历史记录） |
| GET | `/api/matrix` | 许可证兼容矩阵 |
| GET | `/api/sample` | 内置示例 manifest |
| GET | `/api/sample/cyclonedx` | 内置 CycloneDX 示例 BOM |

示例：

```bash
# 上传文件审计
curl -F "file=@static/examples/sample-manifest.json" http://localhost:8000/api/audit/upload

# 按包筛选并导出
curl -OJ "http://localhost:8000/api/audits/1?package=pdf-export&download=true"
```

### 两次审计对比接口

```bash
curl http://localhost:8000/api/audits/compare/1/2
```

路径方向为 **基准 → 目标**：`added` 表示仅目标审计（#2）存在，`removed` 表示仅基准审计（#1）存在。
返回内容：

- `summary.nodes` —— 节点（按 `name@version` 配对）的新增 / 消失 / 配对成功 / 同节点许可证变化数量；
- `summary.findings` —— 冲突/告警的新增、消失、变化数量（并分别统计其中硬冲突数）；
- `added` / `removed` —— 每条携带存在侧的完整冲突对象，含 `path` 最短依赖路径；
  缺失侧固定为 `null`；
- `changed` —— 双方都存在的配对项，同时给出 `base.path` 与 `target.path`，
  `fields_changed` 标明变化项：`severity`（硬冲突⇄告警）、`status`（兼容判定）、
  `ancestor_license` / `node_license`（许可证原文或规范标识变化）、`path`（最短路径变化）；
- `nodes` —— 节点配对明细，含双方许可证、硬冲突数及变化方向。

对比是**只读**操作，不会创建任何审计记录；任一 `audit_id` 不存在时返回 `404`
并指出缺失的编号，传入相同编号返回 `400`：

```bash
$ curl -i http://localhost:8000/api/audits/compare/1/999
HTTP/1.1 404 Not Found
{"detail":"审计记录不存在：#999。对比为只读操作，不会创建新审计。"}

$ curl -i http://localhost:8000/api/audits/compare/3/3
HTTP/1.1 400 Bad Request
{"detail":"请选择两条不同的审计记录进行对比：3 与 3 相同。"}
```

网页端在首页第 2 节「历史审计 · 两次对比」选择两条记录后点击对比即可：
结果按新增 / 消失 / 变化分组，变化项会用 `硬冲突 → 告警` 这类徽标展示严重程度翻转，
并同时渲染双方的最短依赖路径（红色=基准，绿色=目标），折叠区可查看全部节点配对明细。

### 跨审计复核标记接口

复核标记针对**冲突/告警条目**而非某一次审计：指纹由
`祖先节点 id + 被依赖节点 id + 双方规范化许可证 token` 计算（SHA-256），
因此同一依赖关系在任意历史审计中重现时都会命中同一条标记。

**创建标记**（`audit_id` + `conflict_id` 定位条目，指纹由服务端计算）：

```bash
curl -X POST http://localhost:8000/api/reviews \
  -H "Content-Type: application/json" \
  -d '{"audit_id": 1, "conflict_id": "C001",
       "note": "法务已确认，允许组合分发",
       "expires_at": "2026-12-31"}'
```

```json
{
  "id": 1,
  "fingerprint": "d65c257807bfe352…",
  "ancestor": "billing-core@1.2.0", "node": "pdf-export@4.0.0",
  "ancestor_license": "GPL-2.0", "node_license": "Apache-2.0",
  "note": "法务已确认，允许组合分发",
  "expires_at": "2026-12-31T23:59:59+00:00",
  "created_at": "2026-09-23T20:32:22+00:00", "updated_at": "…", "revoked_at": null,
  "state": "active"
}
```

- `note` 可选；`expires_at` 可选，支持 `YYYY-MM-DD`（按当日 23:59:59 UTC）或完整
  ISO 8601（可带时区/`Z`），留空则长期有效；失效时间必须晚于当前时间，否则返回 `422`；
- 同一指纹重复打标时，旧标记自动转为 `superseded`（保留历史），新标记成为唯一有效标记。

**读取审计时自动附着**：`GET /api/audits/{id}`（含 `?package=` 筛选与导出）返回的每条
冲突都带 `review` 字段，`summary.review` 给出计数：

```json
{ "id": "C001", "severity": "error", "…": "原始字段保持不变",
  "review": { "state": "reviewed", "review_id": 1, "note": "法务已确认…",
              "fingerprint": "d65c…", "created_at": "…", "expires_at": null } }
```

无有效标记时 `review.state` 为 `pending`（待复核）。**许可证变更**（指纹不再一致）、
**标记过期**或**被撤销**后，条目自动回到 `pending`。附着只发生在 API 响应层，
数据库中的审计 JSON、冲突严重程度与 `/api/audits/compare/…` 对比结果均不受影响。

**查询与撤销**：

```bash
curl "http://localhost:8000/api/reviews?state=active&limit=50"   # state: active/expired/revoked/superseded
curl "http://localhost:8000/api/reviews?fingerprint=d65c2578…"   # 按指纹查历史
curl http://localhost:8000/api/reviews/1                          # 单条记录
curl -X POST http://localhost:8000/api/reviews/1/revoke           # 撤销（保留记录，条目回到待复核）
```

网页端在第 8 节每条冲突卡片上直接展示「待复核 / 已复核」徽标：待复核条目可填写
复核备注与失效时间后一键打标，已复核条目显示备注、失效时间并提供「撤销标记」按钮，
操作后列表自动刷新。删除审计记录不会删除复核标记（标记按指纹跨审计生效）。

### 根包退役预演接口

根包 = 依赖图中**没有入边**的包（没有任何其他包依赖它）。预演接口从根包集合中
移除选定根包，沿 使用方 → 被依赖方 的边从剩余根包重算可达集合：

```bash
# 不带参数：仅返回该审计的根包列表（rehearsed=false，含每个根包的可达包数量）
curl http://localhost:8000/api/audits/1/retire

# 预演退役一个或多个根包（重复 retire 参数，也支持逗号分隔）
curl "http://localhost:8000/api/audits/1/retire?retire=admin-cli@1.4.0"
curl "http://localhost:8000/api/audits/1/retire?retire=admin-cli@1.4.0&retire=web-app@2.1.0"
```

返回内容（`rehearsed=true` 时）：

- `roots` —— 全部根包（含各自可达包数量 `reachable` 与本次是否被退役 `retired`）；
- `summary` —— 退役前/后可达包数（`reachable_before` / `reachable_after`）、
  失联包数、共用包数、消失冲突数（含其中硬冲突数）；
- `lost` —— 因退役失去可达性的包（`retired_root=true` 为被退役的根包本身，
  其余为仅经退役根包可达的下游包）；
- `shared` —— 退役根包原本可达、但仍被其他剩余根包共用的包
  （`reached_by` 列出这些剩余根包）；
- `disappearing_conflicts` —— 退役后祖先不再能沿依赖边约束到被依赖方的
  许可证冲突/告警，每条附原审计的最短依赖路径 `path` 与 `distance`。

预演是**只读**操作，不会创建审计或改动复核标记；原生 manifest 与 CycloneDX
审计结果均可直接使用。错误情形均返回明确信息：

```bash
$ curl -i "http://localhost:8000/api/audits/999/retire?retire=app@1"
HTTP/1.1 404 Not Found
{"detail":"审计记录不存在：999。退役预演为只读操作，不会创建新审计。"}

$ curl -i "http://localhost:8000/api/audits/1/retire?retire=crypto-lib@1.1.0"
HTTP/1.1 422 Unprocessable Entity
{"detail":"以下包不是根包（仍被其他包依赖，存在入边）：crypto-lib@1.1.0。根包定义为没有入边的包，请改选根包。"}
```

重复选择同一根包（`422`「重复选择退役根包」）、选择审计中不存在的包、
以及退役全部根包（`422`「不能退役全部根包」）同样返回明确错误。
网页端在第 3 节选择审计后勾选根包即可预演，可反复调整勾选重新预演。

### 单包许可证替换预演接口

对一条已保存的审计，仅把**一个包节点**的许可证替换为候选 SPDX 许可证，
沿**原依赖图**（节点与依赖边完全不变）重算传递兼容判定与最短冲突路径，
再按「祖先包 → 被依赖包」配对原结果与预演结果：

```bash
# 不带参数：仅返回该审计的可选包列表与内置矩阵候选许可证（rehearsed=false）
curl http://localhost:8000/api/audits/1/relicense

# 预演：把 legacy-math@0.3.0 的许可证替换为 MIT（包名唯一时也可只给包名）
curl "http://localhost:8000/api/audits/1/relicense?package=legacy-math@0.3.0&license=MIT"
```

返回内容（`rehearsed=true` 时）：

- `target` —— 被替换的包及 `license_before` / `license_after`（含规范化 token 与分类）；
- `summary` —— 硬冲突数（`conflicts_before/after/net`）、告警数
  （`warnings_before/after/net`）与**冲突总数净变化**（`total_before/after/net`），
  以及新增/消失/变化配对数（`added`/`removed`/`changed`，含 `severity_changed`
  等级变化数与新增/消失中的硬冲突数）；
- `comparison` —— 与两次审计对比相同的配对结构：`added`（仅预演结果存在）、
  `removed`（仅原结果存在）、`changed`（两侧都存在但严重程度/判定状态/许可证变化），
  每条记录的 `base` / `target` 两侧均携带完整冲突对象（含各自的最短依赖路径
  `path` 与 `distance`），缺失一侧为 `null`；
- `rehearsal` —— 预演结果的元信息（状态、包数、冲突数等；**没有 `audit_id`**，
  预演不落库）。

候选许可证必须是内置兼容矩阵中的 SPDX 标识（`GET /api/matrix` 或预览接口返回的
`candidate_licenses`，常见别名如 `apache 2` 会自动规范化）；包不存在、包名对应
多个版本（需 `name@version` 消歧）或候选许可证不在矩阵中时返回明确错误：

```bash
$ curl -i "http://localhost:8000/api/audits/999/relicense?package=a@1&license=MIT"
HTTP/1.1 404 Not Found
{"detail":"审计记录不存在：999。许可证替换预演为只读操作，不会创建新审计。"}

$ curl -i "http://localhost:8000/api/audits/1/relicense?package=ghost@9&license=MIT"
HTTP/1.1 422 Unprocessable Entity
{"detail":"审计中不存在包：ghost@9。许可证替换预演只能选择该审计已声明的包节点。"}

$ curl -i "http://localhost:8000/api/audits/1/relicense?package=font-pack@2.0.0&license=OFL-1.1"
HTTP/1.1 422 Unprocessable Entity
{"detail":"候选许可证 'OFL-1.1' 不在内置兼容矩阵中，无法预演。可选 SPDX 标识：MIT、ISC、BSD-2-Clause、…。"}
```

预演是**只读**操作，不会创建审计或改动复核标记；原生 manifest 与 CycloneDX
审计结果均可直接使用。网页端在第 4 节选择审计、包与候选许可证后点击
「预演替换」即可查看净变化统计与三组配对冲突（含两侧最短路径），
可反复更换候选许可证重新预演。

### 未解析依赖补边预演接口

对一条已保存的审计，从 **源包仍存在** 的未解析依赖引用中选一条，再选一个
**现有目标包**，服务端只在内存中补一条 **使用方 → 被依赖方** 的依赖边并移除
该未解析项（其余节点、许可证与边完全不变），重算传递约束与最短冲突路径，
再按「祖先包 → 被依赖包」配对原结果与预演结果：

```bash
# 不带参数：仅返回该审计源包仍存在的未解析引用列表与可选目标包列表（rehearsed=false）
curl http://localhost:8000/api/audits/1/edgefix

# 预演：把 web-app@2.1.0 的未解析引用 cache-redis 绑定到现有包 cache-redis@7.0.0
curl "http://localhost:8000/api/audits/1/edgefix?source=web-app@2.1.0&reference=cache-redis&target=cache-redis@7.0.0"
```

返回内容（`rehearsed=true` 时）：

- `fix` —— 本次补边：`source` / `reference` / `target` 与新补的边
  （`edge.from` 为 `edgefix-rehearsal`），以及请求的原始输入；
- `summary` —— 硬冲突数（`conflicts_before/after/net`）、告警数
  （`warnings_before/after/net`）、**冲突总数净变化**（`total_before/after/net`）
  与未解析数（`unresolved_before/after/net`），以及新增/路径变化配对数
  （`added`/`changed`/`path_changed`，含新增中的硬冲突数 `added_errors`）；
- `comparison` —— 与两次审计对比相同的配对结构：`added`（补边后新增的冲突/告警）、
  `changed`（两侧都存在但**最短依赖路径变化**，`fields_changed` 含 `path`），
  每条记录的 `base` / `target` 两侧均携带完整冲突对象（含各自的最短路径
  `path` 与 `distance`），缺失一侧为 `null`；只增边不改节点，因此 `removed` 恒为空；
- `remaining_unresolved` —— 补边后剩余的未解析依赖项（所选项已被移除）；
- `rehearsal` —— 预演结果的元信息（状态、包数、边数、冲突数等；**没有 `audit_id`**，
  预演不落库）。

`source` + `reference` 精确对应审计 `unresolved` 列表中的一条未解析项
（预览接口原样返回这两个字段），`target` 为现有包节点 id（包名唯一时也可只给包名）。
审计不存在返回 `404`；引用或目标无效、补成自依赖（源包即目标包）或重复边
（源包已依赖目标包）返回 `422`：

```bash
$ curl -i "http://localhost:8000/api/audits/999/edgefix?source=app@1&reference=x@2&target=x@1"
HTTP/1.1 404 Not Found
{"detail":"审计记录不存在：999。补边预演为只读操作，不会创建新审计。"}

$ curl -i "http://localhost:8000/api/audits/1/edgefix?source=app@1&reference=x@2&target=app@1"
HTTP/1.1 422 Unprocessable Entity
{"detail":"不能把 app@1 的未解析引用补成指向自身的边（自依赖）：app@1 -> app@1。请选择其他目标包。"}

$ curl -i "http://localhost:8000/api/audits/1/edgefix?source=app@1&reference=x@2&target=lib@1"
HTTP/1.1 422 Unprocessable Entity
{"detail":"依赖边 app@1 -> lib@1 已存在，补边会产生重复边。请选择其他目标包。"}
```

预演是**只读**操作，不会创建审计或改动复核标记；原生 manifest 与 CycloneDX
审计结果均可直接使用（CycloneDX 中 `ref` 未匹配组件的未解析项源包为 `?`，
不可补边，预览接口会在 `unresolved_skipped` 中单独列出）。网页端在第 5 节
选择审计后，下拉框会列出可选的未解析引用与目标包（自动排除源包自身与
已依赖的目标），点击「预演补边」即可查看净变化统计、新增及路径变化的冲突
（含两侧最短路径）与剩余未解析项，可反复更换选择重新预演。

### 最少断边分析接口

对一条已保存审计中的冲突/告警（祖先包 `ancestor` 沿依赖边约束到被依赖包
`node`），沿审计保存的现有依赖图（**使用方 → 被依赖方**）计算：要让祖先包
**无法再到达**被依赖包，至少要删除哪几条、多少条依赖边。这是有向图上的
**s-t 最小边割**问题，按最大流最小割定理实现：

- 每条现有依赖边容量为 1，用 **Edmonds-Karp（BFS 增广）** 求
  `ancestor → node` 的最大流，最大流流量即**最少断边数**；
- 在最大流残量网络上从祖先包做 BFS，原边中「起点可达、终点不可达」的边
  构成一组**确定性**的最小割边（邻接顺序按审计中边的声明顺序，结果可复现）；
- **并行路径**（多条边不相交路径，需各断一条）、**汇合路径**（多条路径共享
  的瓶颈边，断一条即可）与**依赖环**都在残量网络中自然处理，不只看当前最短路径；
- 返回同等数量的「边不相交」见证路径（每条都恰好被一条建议边截断），
  并在删除建议边后的图上重算 BFS 验证目标确实不再可达。

```bash
curl http://localhost:8000/api/audits/1/edgecut/C007
```

返回内容（节选）：

- `conflict` —— 被分析的冲突/告警条目（id、严重程度、双方许可证与原最短路径信息）；
- `reachable_before` / `original_shortest_path` / `original_distance` ——
  断边前祖先包可达被依赖包，以及**原审计的最短依赖路径**与跳数；
- `cut_count` —— **最少断边数**（等于最大流与边不相交路径数）；
- `cut_edges` —— 一组确定性的建议删除边：`source` / `target` /
  `on_original_shortest_path`（该边是否落在原最短路径上）/ `from`（边来源）；
- `edge_disjoint_paths_count` / `edge_disjoint_paths` ——
  与最少断边数同量的两两边不相交可达路径，说明为什么少于该数量无法切断；
- `reachable_after` —— 删除全部建议边后祖先包是否仍能到达被依赖包（成功时为
  `false`），`residual_shortest_path` 为断边后残留路径（成功时为空），
  `reachable_after_count` 为断边后祖先包仍可达的包数；
- `verification` —— 自洽校验：最小割边数=最大流、边不相交路径数=最大流、
  断边后目标不可达；`deterministic` 恒为 `true`。

```json
{
  "kind": "minimum-edge-cut",
  "read_only": true,
  "deterministic": true,
  "source": "web-app@2.1.0",
  "target": "legacy-math@0.3.0",
  "reachable_before": true,
  "original_shortest_path": ["web-app@2.1.0", "billing-core@1.2.0", "legacy-math@0.3.0"],
  "original_distance": 2,
  "cut_count": 1,
  "cut_edges": [
    {"source": "billing-core@1.2.0", "target": "legacy-math@0.3.0",
     "id": "billing-core@1.2.0 -> legacy-math@0.3.0",
     "from": "package-dependencies", "on_original_shortest_path": true}
  ],
  "edge_disjoint_paths_count": 1,
  "edge_disjoint_paths": [["web-app@2.1.0", "billing-core@1.2.0", "legacy-math@0.3.0"]],
  "reachable_after": false,
  "residual_shortest_path": [],
  "verification": {"mincut_equals_maxflow": true,
                   "edge_disjoint_paths_equals_maxflow": true,
                   "target_unreachable_after_removal": true}
}
```

并行路径示例：祖先经 `p1→p2` 与 `q1→q2` 两条边不相交路径到达目标时
`cut_count` 为 2；两条路径若汇合到共享节点 `m` 后只经 `m→目标` 离开，
则只需删除 `m→目标` 一条边（汇合瓶颈）。

分析是**只读**操作，不会创建审计或改动复核标记；原生 manifest 与 CycloneDX
审计结果均可直接使用。错误情形返回明确信息：

```bash
$ curl -i http://localhost:8000/api/audits/999/edgecut/C001
HTTP/1.1 404 Not Found
{"detail":"审计记录不存在：999。最少断边分析为只读操作，不会创建新审计。"}

$ curl -i http://localhost:8000/api/audits/1/edgecut/C999
HTTP/1.1 404 Not Found
{"detail":"审计 #1 中不存在冲突/告警条目：C999。"}
```

网页端在第 8 节每条冲突/告警卡片上点击「✂ 最少断边分析」即可：
页面展示原最短路径（落在上面的建议断边以红色波浪线标出）、建议删除边清单
（区分原最短路径上的边与并行/汇合路径上的边）、边不相交见证路径（折叠区）
以及断边后是否仍可达的徽标与残留路径；可对任意条目反复分析，
审计结果与复核标记都不会被改动。

### 全图许可证选定接口

对一条**已保存审计**，把每个包从其现有候选许可证（SPDX OR 表达式或多个并列
条目解析出的候选集合；单许可证包候选只有一个，视为固定）中**固定选定一个**，
沿 *使用方 → 被依赖方* 的**全部可达关系**（BFS 传递闭包，含最短可达路径）
逐条调用现有兼容矩阵，求一份全图一致的选择：

```bash
curl http://localhost:8000/api/audits/1/license-select
```

求解是确定性的回溯搜索（MRV 选变量、候选声明顺序选值，按
`(硬冲突数, 告警数)` 字典序分支限界），结论（`status`）分四种：

| `status` | 含义 |
| --- | --- |
| `feasible` | **全图可行**：存在所有可达关系均兼容的选择（硬冲突 0、告警 0） |
| `manual-review` | **需人工确认**：无法全兼容，但存在避开全部硬冲突的选择；`warning_relations` 列出残留的矩阵 warning 关系 |
| `unsolvable` | **无解**：任何选择都至少含一条硬冲突；返回硬冲突最少的选择与 `hard_conflict_relations` 清单 |
| `undetermined` | **未判定**：审计含未知许可证包或未解析依赖；这些包/关系明确列入未判定清单，不声称全图可行。`judged_outcome` 另给已知许可证子图的结论（已知子图本身无解时整体仍为 `unsolvable`） |

返回内容：

- `conclusion` —— 中文结论说明；`has_undetermined` / `judged_outcome` 为机读标记；
- `summary` —— 包数（已知/未知/多候选/固定）、可达关系数、未解析依赖数，
  以及最终选择下的 `relations_ok` / `relations_warning` / `relations_conflict` /
  `relations_undetermined` 计数、`all_relations_compatible` /
  `avoids_hard_conflicts` / `fully_determined` 布尔位与搜索节点数；
- `selections` —— **每包选择**：`selected_token` / `selected_display` /
  `selected_category`、`fixed`（单许可证固定 vs 多候选选定）、`status`
  （`selected` / `unknown-license`）与说明；多候选包同时保留其候选清单；
- `hard_conflict_relations` / `warning_relations` —— 最终选择下仍不兼容的
  关系，每条含 `ancestor` / `node` / 双方 `*_selected` 许可证、矩阵原因与
  BFS `path` 最短可达路径、`distance` 跳数；
- `undetermined_relations` / `unresolved_dependencies` /
  `unknown_license_packages` —— 未判定项：未知许可证导致的关系（标明未知端
  是祖先还是被依赖方）与未解析依赖分别列出。

```json
{
  "kind": "graph-license-selection",
  "read_only": true,
  "deterministic": true,
  "status": "manual-review",
  "judged_outcome": "manual-review",
  "summary": {"packages": 2, "known_packages": 2, "unknown_license_packages": 0,
              "multi_license_packages": 1, "reachable_relations": 1,
              "relations_ok": 0, "relations_warning": 1,
              "relations_conflict": 0, "relations_undetermined": 0,
              "all_relations_compatible": false, "avoids_hard_conflicts": true,
              "fully_determined": true},
  "selections": [
    {"node": {"id": "app@1", "license_display": "Proprietary"},
     "fixed": true, "selected_token": "Proprietary", "selected_category": "proprietary",
     "status": "selected"},
    {"node": {"id": "lib@1", "license_display": "MPL-2.0 OR GPL-2.0"},
     "fixed": false, "selected_token": "MPL-2.0", "selected_category": "weak-copyleft",
     "status": "selected", "reason": "该包声明了 2 个 OR/并列候选，按全图一致方案选定 MPL-2.0。"}
  ],
  "warning_relations": [
    {"ancestor": "app@1", "node": "lib@1", "distance": 1,
     "path": ["app@1", "lib@1"],
     "ancestor_selected": "Proprietary", "node_selected": "MPL-2.0",
     "status": "warning",
     "reason": "MPL-2.0 属于文件/库级弱 copyleft：满足独立链接、可替换及源码提供义务时可被专有作品使用，静态合并则不兼容，需要人工确认链接方式。"}
  ],
  "hard_conflict_relations": [],
  "undetermined_relations": []
}
```

含未知许可证（如 `OFL-1.1`、缺失许可证）或未解析依赖时，对应包
`selections[].status` 为 `unknown-license`、`selected_token` 为 `null`，
关系进入 `undetermined_relations`，结论为 `undetermined`：

```bash
$ curl -s http://localhost:8000/api/audits/999/license-select
{"detail":"审计记录不存在：999。全图许可证选定为只读操作，不会创建新审计。"}
```

审计不存在返回 `404`。分析为纯只读操作，不创建审计、不改动原审计结果
与复核标记；原生 manifest 与 CycloneDX 审计均可直接使用。网页端在第 6 节
选择审计后点击「求全图一致选择」即可查看结论、每包选择与三类关系清单。

### 审计复现包接口（导出 / 离线核验）

复现包把一次历史审计打包成**可离线转交**的单个 JSON 文件：从 SQLite 取出
**原始 manifest** 与**未附着实时复核标记的保存结果**，并附格式版本、审计名称
及两者的 SHA-256 摘要。任何拿到该文件的环境都能通过核验接口确认：
文件自导出后未被改动，且保存的审计结果可由包内 manifest 完整复算。

**导出**（网页第 2 节选择审计后点「⬇ 下载复现包」，或直接调用接口）：

```bash
curl -OJ http://localhost:8000/api/audits/1/repro     # 保存为 audit-1-repro.json
```

复现包结构（`audit-repro/v1`）：

```json
{
  "format": "audit-repro/v1",
  "name": "billing-platform-demo",
  "audit_id": 1,
  "exported_at": "2026-09-25T08:00:00+00:00",
  "digests": {
    "manifest_sha256": "9b6f…", 
    "result_sha256": "41d2…"
  },
  "manifest": { "…": "原始 manifest（SQLite manifest_json）" },
  "result": { "…": "保存的审计结果（未附着复核标记）" }
}
```

`audit_id` 与 `exported_at` 仅为元信息，核验时会被忽略；两处摘要是对
`manifest` / `result` 按**稳定键序列化**（键名排序、紧凑分隔符、UTF-8）
计算的 SHA-256。

**核验**（只读，不创建审计、不改动复核标记）：

```bash
# JSON 请求体
curl -X POST http://localhost:8000/api/repro/verify \
  -H "Content-Type: application/json" \
  --data-binary @audit-1-repro.json

# 或上传复现包文件（网页第 2 节「选择复现包文件 → 上传核验」同源）
curl -F "file=@audit-1-repro.json" http://localhost:8000/api/repro/verify/upload
```

核验流程与判定：

1. **结构校验** —— 格式版本必须为 `audit-repro/v1`，`name` / `digests` /
   `manifest` / `result` 缺一不可，摘要须为 64 位十六进制；不满足时返回
   `422` 并明确指出问题字段；
2. **摘要重算** —— 对包内 `manifest` / `result` 按稳定键序列化重算 SHA-256，
   与包内 `digests` 逐项比对（确认文件未被改动）；
3. **分析器复算** —— 用包内 `manifest` 重新调用现有分析器，剔除审计 ID、
   时间、复核标记等运行元数据后，与保存结果按固定顺序逐项比对
   （`manifest_name → status → summary → nodes → edges → conflicts →
   unresolved → warnings`），节点、依赖边、冲突严重程度与最短路径都在比对之列。

只有**两处摘要与复算结果全部一致**才判通过（`ok: true`）；否则 `ok: false`，
`first_mismatch` 指出首个不一致字段（如 `conflicts[0].severity`）及双方取值：

```json
{
  "kind": "audit-repro-verification",
  "read_only": true,
  "ok": false,
  "format": "audit-repro/v1",
  "name": "billing-platform-demo",
  "checks": [
    { "id": "manifest_digest", "label": "manifest 摘要（SHA-256）", "ok": true, "expected": "9b6f…", "actual": "9b6f…" },
    { "id": "result_digest", "label": "保存结果摘要（SHA-256）", "ok": true, "expected": "41d2…", "actual": "41d2…" },
    { "id": "recompute", "label": "分析器复算比对（剔除审计 id / 时间 / 复核标记）", "ok": false,
      "field": "conflicts[0].severity", "stored": "warning", "recomputed": "error" }
  ],
  "first_mismatch": {
    "check": "recompute",
    "field": "conflicts[0].severity",
    "stored": "warning",
    "recomputed": "error",
    "message": "复算结果与保存结果首个不一致字段为 conflicts[0].severity：保存值 \"warning\"，复算值 \"error\"。"
  },
  "recomputed": { "status": "conflict", "packages": 15, "edges": 15, "conflicts": 9, "…": "…" },
  "message": "复现包核验未通过：复算结果与保存结果首个不一致字段为 conflicts[0].severity：…"
}
```

格式错误返回 `422` 与明确提示：

```bash
$ curl -s -X POST http://localhost:8000/api/repro/verify \
    -H "Content-Type: application/json" -d '{"format": "audit-repro/v99"}'
{"detail":"复现包格式版本不支持：'audit-repro/v99'，应为 'audit-repro/v1'。"}
```

网页端在第 2 节「历史审计 · 两次对比 · 复现包核验」中：左侧下拉选择审计后
「⬇ 下载复现包」；右侧选择复现包文件后点「上传核验」，页面逐项展示
manifest 摘要、保存结果摘要与分析器复算三项校验结果，未通过时高亮
首个不一致字段及双方取值，并给出复算得到的节点/依赖边/冲突统计。

## 审计结果结构（节选）

```json
{
  "audit_id": 1,
  "manifest_name": "billing-platform-demo",
  "status": "conflict",
  "summary": { "packages": 15, "edges": 15, "conflicts": 9, "license_warnings": 4, "unresolved": 1 },
  "nodes": [
    { "id": "pdf-export@4.0.0", "name": "pdf-export", "version": "4.0.0",
      "license_display": "Apache 2.0", "license": "Apache-2.0",
      "license_category": "permissive",
      "license_multi": false,
      "license_candidates": [ {"token": "AGPL-3.0", "display": "AGPL-3.0", "category": "strong-copyleft"} ],
      "license_tokens": ["AGPL-3.0"],
      "constraints": [ { "from": "billing-core@1.2.0", "license": "GPL-2.0", "distance": 1, "status": "conflict" } ] }
  ],
  "conflicts": [
    {
      "id": "C001", "kind": "license-conflict", "severity": "error",
      "ancestor": "billing-core@1.2.0", "node": "pdf-export@4.0.0",
      "ancestor_license": "GPL-2.0", "node_license": "Apache 2.0",
      "ancestor_multi": false, "node_multi": false,
      "distance": 1,
      "path": ["billing-core@1.2.0", "pdf-export@4.0.0"],
      "reason": "GPL-2.0 与 Apache-2.0 专利条款冲突，不能组合进同一作品。",
      "review": { "state": "pending", "fingerprint": "d65c2578…" }
    }
  ],
  "unresolved": [ { "source": "web-app@2.1.0", "reference": "cache-redis", "reason": "依赖包未在 packages 中声明" } ],
  "warnings": ["未解析依赖：web-app@2.1.0 -> cache-redis（依赖包未在 packages 中声明）"]
}
```

CycloneDX 导入的审计结果结构相同，另带 `"source_format": "cyclonedx"` 标识，
且每个节点多一个 `bom_refs` 字段记录映射到该节点的组件 bom-ref。

## 兼容矩阵说明（方向：父作品许可证 → 依赖许可证）

| 父 \ 依赖 | MIT / BSD / ISC / CC0 | Apache-2.0 | MPL-2.0 | LGPL-2.1 / 3.0 | GPL-2.0 | GPL-3.0 | AGPL-3.0 | Proprietary |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| MIT 等宽松型 | ✅ | ✅ | ✅ | ✅* | ✅* | ✅* | ✅* | ⚠️ 授权 |
| MPL-2.0 | ✅ | ✅ | ✅ | 2.1 ❌ / 3.0 ✅ | ❌ | ✅ | ❌ | ❌ |
| LGPL-2.1 | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ 静态合并 |
| LGPL-3.0 | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ 静态合并 |
| GPL-2.0 | ✅ | ❌ 专利条款 | ❌ | 2.1 ✅ / 3.0 ❌ | ✅ | ❌ | ❌ | ❌ |
| GPL-3.0 | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ |
| AGPL-3.0 | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ |
| Proprietary | ✅ | ✅ | ⚠️ 需动态链接 | ⚠️ 需动态链接 | ❌ | ❌ | ❌ | ⚠️ 商业授权 |

`*` 弱/强 copyleft 依赖虽可被宽松作品使用，但其义务会继续向分发链下游传递，本工具会在
`constraints` 中如实记录。完整且带逐条理由的矩阵以 `GET /api/matrix` 返回为准。

> 矩阵依据 SPDX / FSF 对常见许可证组合的通行说明整理，仅用于工程侧自动筛查，
> 不构成法律意见；标记 ⚠️ 与 unknown 的条目请由法务人工确认。

## 项目结构

```
.
├── app/
│   ├── main.py        # FastAPI 路由（JSON API + 网页，含对比/复核/预演/最少断边/复现包接口）
│   ├── analyzer.py    # manifest 解析、节点规范化、传递约束、最短路径（自动路由 CycloneDX）
│   ├── cyclonedx.py   # CycloneDX JSON 导入：bom-ref 映射节点、ref/dependsOn 还原依赖边
│   ├── compare.py     # 两次审计对比：节点/冲突配对与变化检测（纯只读）
│   ├── retire.py      # 根包退役预演：从剩余根包重算可达集合（纯只读）
│   ├── relicense.py   # 单包许可证替换预演：替换一个节点许可证后沿原图重算并配对（纯只读）
│   ├── edgefix.py     # 未解析依赖补边预演：补一条边并移除所选未解析项后重算并配对（纯只读）
│   ├── edgecut.py     # 最少断边分析：Edmonds-Karp 最大流/最小割，确定性断边集合（纯只读）
│   ├── graphselect.py # 全图许可证选定：每包从 OR/并列候选固定选一，全可达关系回溯求一致选择（纯只读）
│   ├── repro.py       # 审计复现包：稳定序列化摘要、导出打包与离线核验（纯只读）
│   ├── reviews.py     # 复核标记：指纹计算、失效时间规范化、审计结果附着
│   ├── licenses.py    # 许可证别名规范化与兼容矩阵
│   └── database.py    # SQLite 初始化与审计记录/复核标记持久化
├── static/
│   ├── index.html     # 单文件网页（无外部 CDN 依赖）
│   └── examples/      # sample-manifest.json 与 sample-cyclonedx.json 两个内置示例
├── tests/             # 轻量自测：python -m tests.test_analyzer / test_compare / test_reviews / test_cyclonedx / test_multi_license / test_retire / test_relicense / test_edgefix / test_edgecut / test_graphselect / test_repro
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```
