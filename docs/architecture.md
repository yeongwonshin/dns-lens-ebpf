# Architecture

## 문제 정의

Kubernetes에서 DNS 장애는 애플리케이션 로그에는 `connection timeout`, `dial tcp`, `no such host`처럼 나타납니다. 하지만 실제 원인은 다음처럼 다양합니다.

- 특정 Pod만 DNS latency가 증가
- CoreDNS upstream 지연
- 특정 도메인만 NXDOMAIN 증가
- Node/CNI 경로 문제
- DNS 서버 응답 누락 또는 packet loss

이 프로젝트는 DNS traffic을 노드에서 관측해 애플리케이션 코드 변경 없이 Pod 단위 DNS 상태를 분석합니다.

## 데이터 경로

1. eBPF TC program이 ingress/egress DNS UDP packet을 관측합니다.
2. DNS header와 question section에서 txid, qname, qtype, rcode를 추출합니다.
3. ring buffer로 user space agent에 이벤트를 전달합니다.
4. agent는 query key를 저장하고 response와 매칭합니다.
5. latency, timeout, NXDOMAIN/SERVFAIL 지표를 Prometheus 형식으로 노출합니다.
6. Kubernetes informer로 Pod IP를 namespace/pod로 변환합니다.

## Query/Response 매칭 키

```text
client_ip + dns_server_ip + txid + qtype + qname
```

response에서는 src/dst가 반대로 오기 때문에 user space에서 역방향 key를 생성합니다.

## Kubernetes Pod 매핑

Pod informer가 다음 mapping을 유지합니다.

```text
PodIP -> namespace/pod/node
```

따라서 eBPF가 packet의 IP만 전달해도 agent는 workload 관점으로 지표를 라벨링할 수 있습니다.

## 알림 정책

기본 알림은 두 가지입니다.

1. 단일 DNS 응답 latency가 `--latency-threshold` 이상
2. query가 `--timeout-window` 안에 response와 매칭되지 않음

운영 환경에서는 단일 이벤트 알림보다 PrometheusRule 기반의 windowed alert를 권장합니다.

## Cardinality 방어

도메인명은 지표 label로 사용되므로 cardinality 폭발 위험이 있습니다.

이 프로젝트는 다음 옵션을 제공합니다.

- `--domain-allow-suffix`: 수집할 도메인 suffix allow-list
- `--domain-deny-suffix`: 제외할 도메인 suffix deny-list
- `--max-domain-labels`: 우측 N개 label만 유지

예: `a.b.c.service.ns.svc.cluster.local` + `max-domain-labels=5` → `service.ns.svc.cluster.local`

## 왜 TC hook인가?

XDP는 빠르지만 packet drop/redirect 중심이고, Pod veth 양방향 관측과 Kubernetes workload context를 다루기에는 TC가 설명하기 쉽습니다. TC ingress/egress는 packet을 통과시키면서 metadata 추출만 수행하기에 DNS latency monitor에 적합한 구조입니다.

## Production 고려사항

- kernel version과 attach 방식 확인
- CNI별 interface naming 확인
- CoreDNS가 NodeLocal DNSCache를 사용하는지 확인
- TCP DNS fallback 관측 필요 여부 확인
- DoH/DoT는 L7 암호화로 이 방식에서 domain 추출 불가
- Prometheus label cardinality 제한 필수
