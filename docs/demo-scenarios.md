# Demo Scenarios

## 1. 정상 DNS latency 확인

```bash
kubectl run dns-ok --image=busybox:1.36 -it --rm --restart=Never -- sh
while true; do nslookup kubernetes.default.svc.cluster.local; sleep 1; done
```

확인 PromQL:

```promql
histogram_quantile(0.95, sum by (le, namespace, pod, domain) (rate(dnsmon_latency_seconds_bucket[5m])))
```

## 2. NXDOMAIN 비율 증가

```bash
kubectl run dns-nxdomain --image=busybox:1.36 -it --rm --restart=Never -- sh
while true; do nslookup random-name-that-does-not-exist.example.com || true; sleep 1; done
```

확인 PromQL:

```promql
sum by (namespace, pod, domain) (rate(dnsmon_nxdomain_total[5m]))
/
clamp_min(sum by (namespace, pod, domain) (rate(dnsmon_queries_total[5m])), 1)
```

## 3. 특정 Pod DNS timeout

테스트 namespace에 NetworkPolicy 또는 iptables로 DNS 응답을 막아 timeout을 만들 수 있습니다. 실제 운영 클러스터에서는 적용 전 반드시 격리된 테스트 namespace에서 검증하세요.

## 4. 특정 도메인 latency 알림

agent 인자 예시:

```bash
--latency-threshold=50ms --domain-allow-suffix=example.com
```

mock 모드에서는 랜덤 latency 이벤트가 발생하므로 alert 로그를 바로 확인할 수 있습니다.

```bash
go run ./cmd/dnsmon --mock --latency-threshold=50ms
```
