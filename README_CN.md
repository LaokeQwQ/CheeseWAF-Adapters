# CheeseWAF Adapters

面向 [CheeseWAF](https://github.com/LaokeQwQ/CheeseWAF) 的 Go-first、自托管网关适配器。

本仓库把网关特定的胶水代码从 CheeseWAF 检测引擎中拆出。默认集成形态是部署在网关或业务旁边的本地 Go 进程（`adapterd`）：它把网关请求上下文转换成版本化检查契约，再把核心决策转换回网关协议。

[English](README.md)

## 当前状态

当前仓库包含版本化契约和可测试的 `adapterd` 骨架，并提供 NGINX `auth_request` 与 Envoy HTTP 授权示例。核心服务地址必须显式配置；核心不可用时，适配器不会静默放行流量。

## 设计原则

- **自托管：** 不依赖 SaaS 控制面、外部遥测服务或厂商账号。
- **Go-first：** 守护进程、契约、测试和后续 sidecar controller 均使用 Go。
- **Sidecar 优先：** 默认以网关或工作负载旁边的本地进程接入，也支持共享部署。
- **适配器保持薄：** 网关包只负责协议转换和响应语义；检测、策略、存储和 ALAP 继续由 CheeseWAF 主仓库负责。
- **Inline 与 OOB 分开：** inline 授权可以阻断；流量镜像只能观测，不能宣称具备实时阻断能力。
- **默认 fail-closed：** 核心不可用时返回 `503 Service Unavailable`；只有显式配置才允许 fail-open。
- **最小化 Body：** 默认不转发请求体，只有策略明确允许时才进入有界 Body 模式。
- **生产依赖边界：** adapterd 发布包和镜像只包含公开适配器契约所需的运行时依赖；开发助手、编辑器集成和本地检查工具不得进入生产制品。

## 架构

    NGINX / Envoy / Kubernetes 网关
                  |
                  | auth_request / ext_authz / ext_proc
                  v
    CheeseWAF-Adapters（Go，adapterd）
                  |
                  | 版本化 HTTP 契约
                  v
    CheeseWAF 核心（自托管，Go）
                  |
                  +-- inline 决策
                  +-- 异步 telemetry / postanalytics

公开仓库包含中英文 README、源代码和运行所需的示例。内部规划和本地 Agent 约束保留在 operator workspace；聊天记录、凭据、运行时状态和私有文件通过 `.gitignore` 排除。

## 集成范围

当前 `adapterd` 提供客户端契约和网关边界。CheeseWAF 核心尚未提供匹配的检查与 telemetry 接口，因此端到端使用必须连接兼容的核心接口或独立 mock；不能把本仓库描述为已经完成 CheeseWAF 集成。未来传输方式和跨集群分析都必须使用独立版本、独立测试的契约，属于可选能力，并置于 inline 授权路径之外。

## 快速开始

环境要求：Go 1.26.6 或更高版本。

    go test ./...
    go run ./cmd/adapterd --listen 127.0.0.1:9080 --core-url http://127.0.0.1:8080

健康检查：

    curl -i http://127.0.0.1:9080/healthz
    curl -i http://127.0.0.1:9080/readyz

适配器会调用配置的核心检查接口（默认路径：`/api/v1/adapter/inspect`），并通过 `/healthz` 为 `readyz` 探测核心。核心服务使用其他路径时，可设置 `CHEESEWAF_CORE_INSPECT_PATH` 和 `CHEESEWAF_CORE_HEALTH_PATH`。规范路径是 `/api/v1/adapter/*`，不是旧文档中的 `/api/v1/check`。

## 网关示例

- NGINX 元数据授权：[adapters/nginx/auth_request.conf](adapters/nginx/auth_request.conf)
- NGINX njs PHP2Shell Body 检查：[adapters/nginx/php2shell-njs.md](adapters/nginx/php2shell-njs.md)
- Envoy：[adapters/envoy/ext_authz.yaml](adapters/envoy/ext_authz.yaml)

`auth_request` 示例只转发元数据，无法检查请求 Body。PHP2Shell 的 Body 检测必须使用 njs access 阶段集成：它在 `proxy_pass` 之前读取并缓存 Body，要求 njs 1.0.2 或更高版本。adapterd 已提供 `POST /nginx/body-check`；需要设置 `CHEESEWAF_ADAPTER_FORWARD_BODY=true` 启用。仅元数据的路由在关闭 Body 转发时会报告 `body_state: withheld`，让核心区分“没有 Body”和“网关没有转发 Body”。

示例使用本机 HTTP hop。生产环境应将适配器限制在私有网络、配置 `CHEESEWAF_ADAPTER_TOKEN`（通过专用 `X-CheeseWAF-Adapter-Token` Header 传入，不读取 `Authorization`），并在跨主机或跨 Pod 时启用 mTLS。非 loopback 的 core URL 必须使用 HTTPS，核心流量不会继承环境 HTTP 代理。只有来自 `CHEESEWAF_ADAPTER_TRUSTED_PROXY_CIDRS` 的对端才会被信任以提供原始/转发请求元数据；NGINX/Envoy 来源缺失原始 URI、method、host、scheme 或客户端地址时会失败关闭。
当 Envoy 报告 `x-envoy-auth-partial-body: true` 时，适配器会把契约 Body 标记为不完整；即使核心返回 `allow`/`log` 或核心超时，也返回 HTTP 413。关闭 Body 转发时则直接拒绝该 partial-body 请求。

## 配置

| 变量 / 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `CHEESEWAF_ADAPTER_LISTEN` / `--listen` | `127.0.0.1:9080` | 适配器监听地址。 |
| `CHEESEWAF_CORE_URL` / `--core-url` | 必填 | 自托管 CheeseWAF 核心地址。非 loopback 必须使用 `https://`；不会继承环境 HTTP 代理。 |
| `CHEESEWAF_CORE_INSPECT_PATH` | `/api/v1/adapter/inspect` | inline 检查接口。 |
| `CHEESEWAF_CORE_TELEMETRY_PATH` | `/api/v1/adapter/telemetry` | 尽力而为的 telemetry 接口。 |
| `CHEESEWAF_CORE_HEALTH_PATH` | `/healthz` | 核心就绪探测接口；为空时关闭客户端探测。如果核心只提供 `/health`，请改为此路径。 |
| `CHEESEWAF_CORE_TOKEN` | 空 | adapterd 发给自托管核心的 Bearer token。 |
| `CHEESEWAF_CORE_TLS_CA_FILE` | 空 | 核心 HTTPS 证书的可选私有 CA bundle。 |
| `CHEESEWAF_CORE_TLS_CERT_FILE` / `CHEESEWAF_CORE_TLS_KEY_FILE` | 空 | 核心 mTLS 的可选客户端证书/私钥对。 |
| `CHEESEWAF_CORE_TLS_SERVER_NAME` | 空 | 核心证书的可选 TLS ServerName 覆盖。 |
| `CHEESEWAF_ADAPTER_TOKEN` | 空 | 网关调用方可选的专用密钥，必须放在 `X-CheeseWAF-Adapter-Token` Header；不读取 `Authorization`，监听非 loopback 时应设置。 |
| `CHEESEWAF_ADAPTER_TRUSTED_PROXY_CIDRS` | `127.0.0.1/32,::1/128` | 允许提供原始/转发请求元数据的对端 CIDR；仅按需扩大到受控代理网段。 |
| `CHEESEWAF_ADAPTER_REQUEST_TIMEOUT` / `--request-timeout` | `100ms` | inline 决策预算。 |
| `CHEESEWAF_ADAPTER_TELEMETRY_TIMEOUT` | `500ms` | telemetry 调用预算。 |
| `CHEESEWAF_ADAPTER_HEALTH_TIMEOUT` | `2s` | 核心就绪探测预算，与 inline 请求预算解耦。 |
| `CHEESEWAF_ADAPTER_HEALTH_CHECK` | `true` | 是否启用 `/readyz` 的核心探测；`false` 时 `/readyz` 返回 disabled。 |
| `CHEESEWAF_ADAPTER_FAIL_MODE` / `--fail-mode` | `closed` | `closed` 返回 `503`；`open` 在核心失败时返回 `204`，并记录 fail-open 日志。 |
| `CHEESEWAF_ADAPTER_FORWARD_BODY` | `false` | 显式开启有界 Body 转发；超过上限时以 `BodyTruncated=true` 发送，若核心返回 `allow`/`log` 则适配器返回 HTTP 413。 |
| `CHEESEWAF_ADAPTER_MAX_BODY_BYTES` | `65536` | 开启 Body 转发时的大小上限（受适配器校验约束）。 |
| `CHEESEWAF_ADAPTER_FORWARD_SENSITIVE_HEADERS` | `false` | 显式允许向自托管核心转发带凭据的 Header。 |

telemetry 接口每次只接受一个经过校验的 JSON event，并按每个 adapterd 进程每秒 100 个事件限速。省略 `contract_version`/`source` 时默认 `v1`/`generic`；先校验再消耗限流额度。`CHEESEWAF_CORE_TELEMETRY_PATH` 为空时路由返回 `503`，不再接受后静默丢弃。健康接口保持便于探针访问；监听地址应保持私有，或配置 adapter token 与网络访问策略。

## 契约边界

`contracts/inspection/v1` 独立于 CheeseWAF 的 `internal` 包，定义以下内容：

- 请求元数据、客户端上下文、TLS 指纹字段和可选响应上下文；
- 显式 `body_state`（`absent`/`withheld`/`forwarded`/`truncated`/`unsupported`）与 `body_encoding`；
- `allow`、`log`、`block`、`challenge` 四种动作；
- policy version、rule ID、响应 Header、多个 `set_cookies`，以及带内容类型白名单的有界 challenge Body；
- Header、authority、path/query、set-cookie 和 body 元数据的失败关闭校验。

新增网关适配器必须使用这个契约或后续版本化契约。适配器不得复制检测器逻辑，也不得 import 核心仓库的 `internal/...` 包。

## 路线图

1. 完善 HTTP `auth_request` 和 Envoy `ext_authz` conformance 测试。
2. 只有在确实需要有界 Body 或响应检查时，才增加流式 Envoy `ext_proc` 适配器。
3. 增加 Kubernetes sidecar controller，使用 opt-in annotation 和显式 Service 路由；特权 iptables 注入保持可选。
4. 增加签名 policy snapshot、last-known-good 回滚和异步 postanalytics/OOB mirror 接收。
5. 在核心契约完成兼容性测试后，再增加 Kong、APISIX 和 Traefik 适配器。
6. 只有出现明确的 NGINX 原生模块需求时，才考虑单独的 NGINX C ABI shim；WAF 逻辑仍必须留在 Go。

## 许可证

Apache-2.0，详见 [LICENSE](LICENSE)。
