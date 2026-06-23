# Troubleshooting

## eBPF object load 실패

확인 항목:

```bash
uname -a
bpftool feature probe kernel
ulimit -l
```

권한이 부족하면 DaemonSet의 `privileged: true`, `NET_ADMIN`, `BPF`, `PERFMON`, `SYS_RESOURCE` capability를 확인하세요.

## attach 실패

이 예시는 TCX attach를 사용합니다. 구형 kernel에서는 classic tc filter attach fallback이 필요할 수 있습니다.

확인:

```bash
ip link
tc filter show dev <iface> ingress
tc filter show dev <iface> egress
```

## Pod 라벨이 unknown으로 보임

- ServiceAccount RBAC이 pods list/watch 권한을 가지는지 확인
- Pod가 hostNetwork이거나 PodIP가 아닌 Node IP traffic인지 확인
- dual-stack cluster에서는 IPv6 지원을 추가해야 함

## 지표 cardinality가 너무 큼

다음 옵션으로 제한하세요.

```bash
--domain-allow-suffix=svc.cluster.local,company.internal
--max-domain-labels=5
```

## DNS 응답이 unmatched로 표시됨

가능한 원인:

- query와 response가 서로 다른 interface에서만 관측됨
- DNS response question section이 압축되어 eBPF parser가 skip함
- TCP fallback 또는 DoH/DoT 사용
- DNS cache hit로 실제 외부 query가 발생하지 않음
