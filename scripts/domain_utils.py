"""도메인 비교용 작은 공용 유틸리티."""

COMMON_MULTI_LABEL_SUFFIXES = {
    "co.kr", "or.kr", "go.kr", "ne.kr", "pe.kr",
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "co.jp", "ne.jp", "or.jp",
    "com.br", "com.cn", "com.sg", "com.tw",
}


def normalize_domain(value):
    return str(value or "").strip().strip(".").lower()


def domain_is_or_subdomain(value, parent):
    """value가 parent 자체이거나 그 하위 도메인인 경우만 True."""
    value, parent = normalize_domain(value), normalize_domain(parent)
    return bool(value and parent and (value == parent or value.endswith("." + parent)))


def matches_any_domain(value, parents):
    return any(domain_is_or_subdomain(value, p) for p in parents)


def registrable_domain(value):
    """외부 의존성 없이 흔한 다중 라벨 공용접미사를 고려한 eTLD+1."""
    labels = normalize_domain(value).split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    suffix2 = ".".join(labels[-2:])
    return ".".join(labels[-3:]) if suffix2 in COMMON_MULTI_LABEL_SUFFIXES else suffix2


def is_public_suffix(value):
    value = normalize_domain(value)
    return "." not in value or value in COMMON_MULTI_LABEL_SUFFIXES


def domain_content(value):
    """Suricata PCRE 등에 넣기 전 정규화된 도메인."""
    return normalize_domain(value)
