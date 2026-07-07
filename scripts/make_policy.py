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
import sys, os, json, re, subprocess

SID_BASE = 1000000
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_DOM = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)*\.[a-z]{2,}$", re.I)


def _valid_ip(s):
    if not _IPV4.match(str(s)):
        return False
    return all(0 <= int(o) <= 255 for o in str(s).split("."))


def make_rules(report):
    """report → (rules[list[str]], skipped[list[(kind,value)]]). 순수 함수, 결정론."""
    a = report.get("analysis") or {}
    iocs = a.get("iocs", {})
    attacks = a.get("attacks") or []

    block_ips = {ip for b in ("c2", "delivery", "exfil") for ip in iocs.get(b, [])}
    block_ips |= {t["actor"] for t in attacks
                  if t.get("actor_scope") == "external" and t.get("actor")}
    isolate = {t["actor"] for t in attacks
               if t.get("actor_scope") == "internal" and t.get("actor")}
    block_ips -= isolate                       # 내부 호스트는 IP차단 아니라 격리 룰로만
    block_doms = set(iocs.get("domains", []))

    rules, sid, skipped = [], SID_BASE, []
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
        print(f"[policy] 건너뜀(형식오류) {len(skipped)}: {skipped[:5]}")
    if "--validate" in sys.argv:
        ok, msg = validate(out)
        tag = "PASS" if ok else ("SKIP(suricata 없음)" if ok is None else "FAIL")
        print(f"[validate] {tag}")
        if ok is False:
            print(msg[-800:])


if __name__ == "__main__":
    main()
