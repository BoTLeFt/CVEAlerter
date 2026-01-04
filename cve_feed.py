from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import html
import json
import re
from typing import Iterable, List, Optional
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET

from config import CIRCL_URL_TEMPLATE, USER_AGENT


@dataclass(frozen=True)
class CveItem:
    title: str
    link: str
    description: str
    published_at: Optional[datetime]


def fetch_rss(url: str) -> str:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=15) as resp:
        return resp.read().decode("utf-8", errors="replace")


def fetch_json(url: str) -> Optional[dict]:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=20) as resp:
            payload = resp.read().decode("utf-8", errors="replace")
    except HTTPError:
        return None
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return None


def parse_items(rss_xml: str) -> List[CveItem]:
    root = ET.fromstring(rss_xml)
    items: List[CveItem] = []
    for item in root.findall(".//item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        description = (item.findtext("description") or "").strip()
        pub_date_raw = (item.findtext("pubDate") or "").strip()
        published_at = parse_pub_date(pub_date_raw)
        items.append(
            CveItem(
                title=title,
                link=link,
                description=description,
                published_at=published_at,
            )
        )
    return items


def filter_recent(items: Iterable[CveItem], window: timedelta) -> List[CveItem]:
    now = datetime.now(timezone.utc)
    cutoff = now - window
    recent_items = []
    for item in items:
        if item.published_at is None:
            continue
        if item.published_at.tzinfo is None:
            published_at = item.published_at.replace(tzinfo=timezone.utc)
        else:
            published_at = item.published_at.astimezone(timezone.utc)
        if published_at >= cutoff:
            recent_items.append(item)
    return recent_items


def filter_critical_by_cvss(
    items: Iterable[CveItem], circl_cache: dict, threshold: float
) -> List[CveItem]:
    critical_items = []
    for item in items:
        cvss_value = get_item_cvss(item, circl_cache)
        if cvss_value is not None and cvss_value > threshold:
            critical_items.append(item)
    return critical_items


def parse_pub_date(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None


def clean_html(text: str) -> str:
    text = text.replace("<br>", "\n").replace("<br/>", "\n").replace("<br />", "\n")
    text = re.sub(r"<[^>]+>", "", text)
    text = html.unescape(text)
    lines = [line.strip() for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def parse_fields(description_text: str) -> dict:
    fields = {"cve_id": "", "cvss_score": "", "description": ""}
    for line in description_text.splitlines():
        if not fields["cve_id"]:
            match = re.search(r"\bCVE-\d{4}-\d+\b", line)
            if match:
                fields["cve_id"] = match.group(0)
        if not fields["cvss_score"]:
            match = re.search(r"Severity:\s*([0-9]+(?:\.[0-9]+)?)", line, re.I)
            if match:
                fields["cvss_score"] = match.group(1)
        if not fields["description"] and line.lower().startswith("description"):
            fields["description"] = line.split(":", 1)[-1].strip()
    if not fields["description"]:
        fields["description"] = description_text
    return fields


def extract_cve_id(title: str) -> str:
    match = re.search(r"\bCVE-\d{4}-\d+\b", title)
    return match.group(0) if match else ""


def extract_circl_cvss(details: dict) -> Optional[float]:
    cna = details.get("containers", {}).get("cna", {})
    metrics = cna.get("metrics", [])
    for metric in metrics:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV2_0"):
            data = metric.get(key)
            if isinstance(data, dict) and "baseScore" in data:
                return data["baseScore"]
    return details.get("cvss")


def cvss_to_float(value: Optional[object]) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def extract_circl_summary(details: dict) -> str:
    cna = details.get("containers", {}).get("cna", {})
    descriptions = cna.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en" and desc.get("value"):
            return desc["value"]
    return details.get("summary") or ""


def extract_circl_cwe(details: dict) -> str:
    cna = details.get("containers", {}).get("cna", {})
    problem_types = cna.get("problemTypes", [])
    for entry in problem_types:
        for desc in entry.get("descriptions", []):
            cwe_id = desc.get("cweId")
            if cwe_id:
                return cwe_id
    return details.get("cwe") or ""


def extract_circl_references(details: dict) -> List[str]:
    cna = details.get("containers", {}).get("cna", {})
    references = []
    for ref in cna.get("references", []):
        url = ref.get("url")
        if url:
            references.append(url)
    if references:
        return references
    raw = details.get("references")
    return raw if isinstance(raw, list) else []


def format_version_range(version_entry: dict) -> str:
    version = str(version_entry.get("version") or "").strip()
    lte = str(version_entry.get("lessThanOrEqual") or "").strip()
    lt = str(version_entry.get("lessThan") or "").strip()
    if lte:
        if version and version != lte:
            return f"{version}..<= {lte}"
        return version or f"<= {lte}"
    if lt:
        if version and version != lt:
            return f"{version}..< {lt}"
        return version or f"< {lt}"
    return version


def extract_circl_affected_products(details: dict) -> List[str]:
    cna = details.get("containers", {}).get("cna", {})
    affected = cna.get("affected", [])
    products = []
    for item in affected:
        product = item.get("product") or ""
        vendor = item.get("vendor") or ""
        name = f"{vendor} {product}".strip() if vendor else product
        versions = []
        for version_entry in item.get("versions", []):
            status = (version_entry.get("status") or "").lower()
            if status and status != "affected":
                continue
            formatted = format_version_range(version_entry)
            if formatted:
                versions.append(formatted)
        if name:
            version_text = ", ".join(versions) if versions else "N/A"
            products.append(f"{name}:{version_text}")
    if products:
        return products
    raw = details.get("vulnerable_product")
    if isinstance(raw, list):
        return [f"{entry}:N/A" for entry in raw]
    return []


def get_circl_details(cve_id: str, cache: dict) -> dict:
    if not cve_id:
        return {}
    if cve_id in cache:
        return cache[cve_id]
    url = CIRCL_URL_TEMPLATE.format(cve_id=cve_id)
    payload = fetch_json(url) or {}
    cache[cve_id] = payload
    return payload


def get_item_cvss(item: CveItem, circl_cache: dict) -> Optional[float]:
    description_clean = clean_html(item.description) if item.description else ""
    fields = parse_fields(description_clean)
    cve_id = fields["cve_id"] or extract_cve_id(item.title)
    details = get_circl_details(cve_id, circl_cache)
    cvss = extract_circl_cvss(details) or fields["cvss_score"]
    return cvss_to_float(cvss)
