#!/usr/bin/env python3
"""
차단정책 생성 (파이프라인 5단계): reports/<name>.json → Suricata drop 룰.

  python3 scripts/make_policy.py <name> [--validate]
    입력:  reports/<name>.json   (분석 산출물, iocs 이미 정제됨)
    출력:  reports/<name>.rules  (Suricata 룰)

원칙(대화에서 확정):
  - chat() 없음. 정제된 IOC 를 룰 템플릿에 결정론적으로 끼워넣기만 → 재오염 방지.
    같은 report → 같은 룰/sid (sort+dedup) 라 재실행·diff 안전.
  - 안전은 상류에서 이미 보장: 피격자(attacks.target)·내부 자산은
    annotate_attacks/ground_iocs 가 이미 iocs 에서 제거했다 → 여기 남은 IP/도메인은
    '진짜 외부 악성'으로 신뢰하고 룰로 만든다.
  - scope 분기: 외부 actor = IP 차단 / 내부 actor = 호스트 격리 / target = 룰 없음.
  - 각 값은 형식검증(유효 IPv4 / 도메인) 통과분만 룰화 — 깨진 값이 룰로 새는 것 방지.
  - 해시는 보류(사용자 결정 대기).
"""
import sys, os, json, re, subprocess, ipaddress

SID_BASE = 1000000
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_DOM = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)*\.[a-z]{2,}$", re.I)


def _valid_ip(s):
    if not _IPV4.match(str(s)):
        return False
    return all(0 <= int(o) <= 255 for o in str(s).split("."))


# 공유 CDN 엣지 대역 (사업자 공시 소유대역). 이 IP 는 수천 사이트가 공유하는 엣지라
# drop ip 로 막으면 Cloudflare/Fastly 전체가 막힌다(부수피해). 악성 '도메인'은
# tls.sni/dns.query 룰이 공유 IP 위에서도 그 호스트만 정확히 잡으므로, CDN IP 는
# IP차단에서 빼고 도메인 룰에 맡긴다. (Cloudflare: cloudflare.com/ips-v4, Fastly 주대역)
_CDN_NETS = [ipaddress.ip_network(c) for c in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",   # ── Cloudflare
    "151.101.0.0/16",                                     # ── Fastly
)]


def _is_cdn(ip):
    try:
        return any(ipaddress.ip_address(ip) in n for n in _CDN_NETS)
    except ValueError:
        return False


def _priv(ip):
    """사설(내부) IPv4 여부. 외부 IP 를 격리룰로 잘못 내보내는 것 방지."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def make_rules(report):
    """report → (rules[list[str]], skipped[list[(kind,value)]]). 순수 함수, 결정론."""
    a = report.get("analysis") or {}
    iocs = a.get("iocs", {})
    attacks = a.get("attacks") or []
    victims = a.get("victims") or []

    # 인프라(DC/DNS)는 자동 격리 대상에서 제외 — DC 를 drop any->any 로 끊으면 AD 전체가
    # 서비스 자폭. 인프라는 '패치·조사' 대상이지 격리 대상이 아니며, 보고서에 compromised 로
    # 남아 사람이 판단한다(프로젝트 목표: 최종 o/x 는 사람). role 은 run.py 가 evidence 로 확정.
    role_of = {str(v.get("ip")): v.get("role") for v in victims if v.get("ip")}
    def _is_infra(ip):
        return bool(ip) and role_of.get(str(ip)) in ("domain_controller", "dns_server")

    block_ips = {ip for b in ("c2", "delivery", "exfil") for ip in iocs.get(b, [])}
    block_ips |= {t["actor"] for t in attacks
                  if t.get("actor_scope") == "external" and t.get("actor")}
    isolate = {t["actor"] for t in attacks
               if t.get("actor_scope") == "internal" and t.get("actor") and not _is_infra(t["actor"])}
    # 침해 확정된 내부 호스트도 격리(공격자든 워크스테이션 타겟이든). 외부 IP 오분류 방어로
    # 사설대역만. 단 인프라(DC/DNS)는 제외 — 위 자폭 방지.
    isolate |= {v["ip"] for v in victims
                if v.get("status") == "compromised" and _priv(v.get("ip") or "")
                and not _is_infra(v.get("ip"))}
    # 인프라라서 격리에서 뺀 침해 호스트는 침묵하지 않고 사유를 남긴다(사람 검토 유도)
    infra_skipped = [(str(v.get("ip")), v.get("role")) for v in victims
                     if v.get("status") == "compromised" and _priv(v.get("ip") or "")
                     and _is_infra(v.get("ip"))]
    block_ips -= isolate                       # 내부 호스트는 IP차단 아니라 격리 룰로만
    block_doms = set(iocs.get("domains", []))

    rules, sid, skipped = [], SID_BASE, []
    for ip, role in infra_skipped:             # 인프라 격리 제외분 노출 (사람 검토: 패치/조사)
        skipped.append((f"isolate-infra:{role}(패치/조사대상)", ip))
    cdn_ips = {ip for ip in block_ips if _valid_ip(ip) and _is_cdn(ip)}
    block_ips -= cdn_ips                        # ── 공유 CDN 엣지: IP-drop 제외(부수피해 방지) ──
    for ip in sorted(cdn_ips):                  #    조용히 버리지 않고 사유를 남긴다(도메인룰이 대체)
        tag = "cdn-ip:도메인룰로대체" if block_doms else "cdn-ip:!경고-막을도메인없음-수동확인"
        skipped.append((tag, ip))
    for ip in sorted(block_ips):               # ── 외부 악성 IP: 아웃바운드 drop ──
        if not _valid_ip(ip):
            skipped.append(("ip", ip)); continue
        rules.append(f'drop ip $HOME_NET any -> {ip} any '
                     f'(msg:"[AUTO] BLOCK ioc {ip}"; classtype:trojan-activity; '
                     f'sid:{sid}; rev:1;)'); sid += 1
    for dom in sorted(block_doms):             # ── 도메인: DNS 조회 + TLS SNI 둘 다 ──
        d = str(dom).lower()
        if not _DOM.match(d):
            skipped.append(("domain", dom)); continue
        rules.append(f'drop dns $HOME_NET any -> any any '
                     f'(msg:"[AUTO] BLOCK dns {d}"; dns.query; content:"{d}"; nocase; '
                     f'sid:{sid}; rev:1;)'); sid += 1
        rules.append(f'drop tls $HOME_NET any -> any any '
                     f'(msg:"[AUTO] BLOCK sni {d}"; tls.sni; content:"{d}"; nocase; '
                     f'sid:{sid}; rev:1;)'); sid += 1
    for host in sorted(isolate):               # ── 내부 침해 발판: 호스트 격리 ──
        if not _valid_ip(host):
            skipped.append(("isolate", host)); continue
        rules.append(f'drop ip {host} any -> any any '
                     f'(msg:"[AUTO] ISOLATE compromised host {host}"; sid:{sid}; rev:1;)'); sid += 1
    # 해시: 보류 (Suricata filesha256 은 평문HTTP 한정 + 전송완료 후 판정 → EDR 병행이 맞아 대기)
    return rules, skipped


def validate(path):
    """suricata -T 로 룰 문법 검증. (없으면 None, 실패 False, 통과 True)"""
    cfg = "/etc/suricata/suricata.yaml"
    cmd = ["suricata", "-T", "-S", path, "-l", "/tmp"]
    if os.path.exists(cfg):
        cmd[1:1] = ["-c", cfg]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        return (r.returncode == 0), (r.stderr or r.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return None, str(e)


def main():
    if len(sys.argv) < 2:
        raise SystemExit("사용법: python3 scripts/make_policy.py <name> [--validate]")
    name = sys.argv[1]
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(ROOT, "reports", f"{name}.json"), encoding="utf-8") as f:
        report = json.load(f)
    rules, skipped = make_rules(report)
    out = os.path.join(ROOT, "reports", f"{name}.rules")
    header = [f"# auto-generated Suricata policy for {name}",
              f"# {len(rules)} rules — 사람 검토 후 적용 (drop = 인라인/IPS 모드에서만 실제 차단)",
              "# HOME_NET 은 suricata.yaml 에 정의되어 있어야 함"]
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(header + [""] + rules) + "\n")
    print(f"[policy] {out}  ({len(rules)} rules)")
    if skipped:
        print(f"[policy] 건너뜀 {len(skipped)}건: {skipped[:8]}")
    if "--validate" in sys.argv:
        ok, msg = validate(out)
        tag = "PASS" if ok else ("SKIP(suricata 없음)" if ok is None else "FAIL")
        print(f"[validate] {tag}")
        if ok is False:
            print(msg[-800:])


if __name__ == "__main__":
    main()
