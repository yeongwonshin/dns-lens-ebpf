# eBPF 기반 DNS Latency Monitor

Kubernetes 환경에서 DNS query/response를 eBPF로 관측하고, 도메인·Pod 단위 latency, NXDOMAIN 비율, timeout을 분석하는 포트폴리오용 Observability 프로젝트입니다.

> 목표: “DNS가 느리다”를 `어떤 Pod가`, `어떤 도메인에`, `어떤 DNS 서버를 통해`, `얼마나 느리게/실패했는지`까지 설명할 수 있게 만들기.

## 핵심 기능

- eBPF TC 프로그램으로 UDP DNS 패킷 관측
- DNS query/response correlation
- domain별 latency histogram
- NXDOMAIN/SERVFAIL 비율 집계
- timeout 감지
- Kubernetes Pod IP → namespace/pod/container 매핑
- 특정 도메인 latency 임계치 초과 시 알림
- Prometheus `/metrics` 제공
- Grafana dashboard 예시 제공

## 아키텍처

```text
+--------------------+      ringbuf       +-------------------------+
| Linux Kernel       | -----------------> | dnsmon-agent            |
| TC eBPF ingress/   |                    | - query/response match  |
| egress parser      |                    | - timeout scanner       |
+--------------------+                    | - pod cache             |
        |                                 | - prometheus exporter   |
        |                                 +-----------+-------------+
        |                                             |
        v                                             v
 Pod DNS traffic                              Prometheus / Grafana
```

## 디렉토리 구조

```text
.
├── bpf/                         # eBPF C 프로그램
├── cmd/dnsmon/                  # Go entrypoint
├── internal/                    # metrics, pod cache, alert, DNS correlation
├── deploy/kubernetes/           # RBAC, ConfigMap, DaemonSet, ServiceMonitor
├── dashboards/                  # Grafana dashboard JSON
├── docs/                        # 설계/운영 문서
├── scripts/                     # 개발/데모 스크립트
├── testdata/                    # 테스트/부하 발생 매니페스트
├── Dockerfile
├── Makefile
└── go.mod
```

## 빠른 실행

### 로컬 mock 모드

macOS나 eBPF 권한이 없는 환경에서도 설계 흐름을 확인할 수 있습니다.

```bash
go run ./cmd/dnsmon --mock --metrics-addr=:9090
curl localhost:9090/metrics | grep dnsmon
```

### Linux 노드에서 eBPF 빌드

```bash
make generate
make build
sudo ./bin/dnsmon --iface-prefix=veth,cali,cilium,flannel,eth --metrics-addr=:9090
```

### Kubernetes 배포

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/rbac.yaml
kubectl apply -f deploy/kubernetes/configmap.yaml
kubectl apply -f deploy/kubernetes/daemonset.yaml
kubectl apply -f deploy/kubernetes/service.yaml
```

Prometheus Operator를 사용한다면:

```bash
kubectl apply -f deploy/kubernetes/servicemonitor.yaml
```

## 주요 Prometheus 지표

| Metric | 설명 |
|---|---|
| `dnsmon_queries_total` | Pod/domain/rcode별 DNS response 수 |
| `dnsmon_latency_seconds` | Pod/domain/server별 DNS latency histogram |
| `dnsmon_timeouts_total` | query 이후 timeout window 내 response 미수신 |
| `dnsmon_nxdomain_total` | NXDOMAIN 응답 수 |
| `dnsmon_inflight_queries` | 아직 response가 매칭되지 않은 query 수 |
| `dnsmon_alerts_total` | 임계치 초과 알림 발생 수 |

## 면접 어필 포인트

1. **실무 문제성**: DNS 장애는 서비스 장애처럼 보이지만 원인 추적이 어렵습니다.
2. **커널/네트워크 이해**: eBPF TC hook에서 L2/L3/L4/DNS를 직접 파싱합니다.
3. **Kubernetes 이해**: Pod IP cache를 통해 노드 단위 패킷을 workload 관점으로 변환합니다.
4. **SRE 관점**: latency histogram, timeout, NXDOMAIN ratio, alert rule까지 설계했습니다.
5. **확장성**: CoreDNS 로그가 없어도 노드에서 관측 가능하며, service mesh와 독립적입니다.

## 한계와 개선 방향

- TCP DNS, DoT/DoH는 기본 범위에서 제외했습니다.
- DNS compression이 들어간 일부 response의 질문부 파싱은 제한적입니다.
- attach 방식은 TCX 중심 예시이며, 구형 커널에서는 classic tc attach fallback을 추가해야 합니다.
- production에서는 domain label cardinality 제어가 중요합니다.

자세한 내용은 `docs/architecture.md`, `docs/demo-scenarios.md`, `docs/troubleshooting.md`를 참고하세요.
