from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import html
import json
import re
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET

from config import (
    CIRCL_URL_TEMPLATE,
    CVEORG_URL_TEMPLATE,
    NVD_URL_TEMPLATE,
    OSV_URL_TEMPLATE,
    SOURCE_PRIORITY,
    USER_AGENT,
)


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


def extract_nvd_cvss(details: dict) -> Optional[float]:
    """Extract CVSS score from NVD format (API 2.0)."""
    metrics = details.get("metrics", {})
    if not metrics:
        return None
    
    # NVD API 2.0 format: metrics is a dict with arrays
    # Try CVSS v3.1 first (most recent)
    cvss_v31 = metrics.get("cvssMetricV31", [])
    if cvss_v31 and isinstance(cvss_v31, list) and len(cvss_v31) > 0:
        cvss_data = cvss_v31[0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        if score is not None:
            return cvss_to_float(score)
    
    # Try CVSS v3.0
    cvss_v30 = metrics.get("cvssMetricV30", [])
    if cvss_v30 and isinstance(cvss_v30, list) and len(cvss_v30) > 0:
        cvss_data = cvss_v30[0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        if score is not None:
            return cvss_to_float(score)
    
    # Try CVSS v2.0
    cvss_v2 = metrics.get("cvssMetricV2", [])
    if cvss_v2 and isinstance(cvss_v2, list) and len(cvss_v2) > 0:
        cvss_data = cvss_v2[0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        if score is not None:
            return cvss_to_float(score)
    
    return None


def extract_osv_cvss(details: dict) -> Optional[float]:
    """Extract CVSS score from OSV format."""
    database_specific = details.get("database_specific", {})
    cvss_score = database_specific.get("cvss_score")
    if cvss_score is not None:
        return cvss_to_float(cvss_score)
    # OSV may have severity field
    severity = details.get("severity", [])
    for sev in severity:
        if sev.get("type") == "CVSS_V3":
            score = sev.get("score")
            if score is not None:
                return cvss_to_float(score)
    return None


def extract_circl_cvss(details: dict) -> Optional[float]:
    """Extract CVSS score from CIRCL format."""
    cna = details.get("containers", {}).get("cna", {})
    metrics = cna.get("metrics", [])
    for metric in metrics:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV2_0"):
            data = metric.get(key)
            if isinstance(data, dict) and "baseScore" in data:
                return data["baseScore"]
    return details.get("cvss")


def extract_cveorg_cvss(details: dict) -> Optional[float]:
    """Extract CVSS score from CVE.org (MITRE) format."""
    # CVE.org uses CVE 5.0 format, similar to CIRCL
    cna = details.get("containers", {}).get("cna", {})
    metrics = cna.get("metrics", [])
    for metric in metrics:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV2_0"):
            data = metric.get(key)
            if isinstance(data, dict) and "baseScore" in data:
                return cvss_to_float(data["baseScore"])
    return None


def extract_cvss(details: dict) -> Optional[float]:
    """Extract CVSS score from merged data."""
    # Use merged CVSS if available
    if "_cvss" in details:
        return cvss_to_float(details["_cvss"])
    # Fallback to old format for backward compatibility
    return cvss_to_float(details.get("cvss"))


def cvss_to_float(value: Optional[object]) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def extract_nvd_summary(details: dict) -> str:
    """Extract summary from NVD format."""
    descriptions = details.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en" and desc.get("value"):
            return desc["value"]
    return ""


def extract_osv_summary(details: dict) -> str:
    """Extract summary from OSV format."""
    return details.get("summary", "") or details.get("details", "")


def extract_circl_summary(details: dict) -> str:
    """Extract summary from CIRCL format."""
    cna = details.get("containers", {}).get("cna", {})
    descriptions = cna.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en" and desc.get("value"):
            return desc["value"]
    return details.get("summary") or ""


def extract_cveorg_summary(details: dict) -> str:
    """Extract summary from CVE.org (MITRE) format."""
    cna = details.get("containers", {}).get("cna", {})
    descriptions = cna.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en" and desc.get("value"):
            return desc["value"]
    return ""


def extract_summary(details: dict) -> str:
    """Extract summary from merged data."""
    # Use merged summary if available
    if "_summary" in details:
        return details["_summary"]
    # Fallback to old format for backward compatibility
    return details.get("summary", "")


def extract_nvd_cwe(details: dict) -> str:
    """Extract CWE from NVD format."""
    weaknesses = details.get("weaknesses", [])
    for weakness in weaknesses:
        descriptions = weakness.get("description", [])
        for desc in descriptions:
            value = desc.get("value")
            if value and value.startswith("CWE-"):
                return value
    return ""


def extract_osv_cwe(details: dict) -> str:
    """Extract CWE from OSV format."""
    database_specific = details.get("database_specific", {})
    cwe_ids = database_specific.get("cwe_ids", [])
    if cwe_ids:
        return cwe_ids[0]
    return ""


def extract_circl_cwe(details: dict) -> str:
    """Extract CWE from CIRCL format."""
    cna = details.get("containers", {}).get("cna", {})
    problem_types = cna.get("problemTypes", [])
    for entry in problem_types:
        for desc in entry.get("descriptions", []):
            cwe_id = desc.get("cweId")
            if cwe_id:
                return cwe_id
    return details.get("cwe") or ""


def extract_cveorg_cwe(details: dict) -> str:
    """Extract CWE from CVE.org (MITRE) format."""
    cna = details.get("containers", {}).get("cna", {})
    problem_types = cna.get("problemTypes", [])
    for entry in problem_types:
        for desc in entry.get("descriptions", []):
            cwe_id = desc.get("cweId")
            if cwe_id:
                return cwe_id
    return ""


def extract_cwe(details: dict) -> str:
    """Extract CWE from merged data."""
    # Use merged CWE if available
    if "_cwe" in details:
        return details["_cwe"]
    # Fallback to old format for backward compatibility
    return details.get("cwe", "")


def extract_nvd_references(details: dict) -> List[str]:
    """Extract references from NVD format."""
    references = details.get("references", [])
    urls = []
    for ref in references:
        url = ref.get("url")
        if url:
            urls.append(url)
    return urls


def extract_osv_references(details: dict) -> List[str]:
    """Extract references from OSV format."""
    references = details.get("references", [])
    urls = []
    for ref in references:
        if isinstance(ref, dict):
            url = ref.get("url")
        elif isinstance(ref, str):
            url = ref
        else:
            continue
        if url:
            urls.append(url)
    return urls


def extract_circl_references(details: dict) -> List[str]:
    """Extract references from CIRCL format."""
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


def extract_cveorg_references(details: dict) -> List[str]:
    """Extract references from CVE.org (MITRE) format."""
    cna = details.get("containers", {}).get("cna", {})
    references = []
    for ref in cna.get("references", []):
        url = ref.get("url")
        if url:
            references.append(url)
    return references


def extract_references(details: dict) -> List[str]:
    """Extract references from merged data."""
    # Use merged references if available
    if "_references" in details:
        return details["_references"]
    # Fallback to old format for backward compatibility
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


def extract_nvd_affected_products(details: dict) -> List[str]:
    """Extract affected products from NVD format."""
    configurations = details.get("configurations", [])
    products = []
    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            cpe_match = node.get("cpeMatch", [])
            for match in cpe_match:
                criteria = match.get("criteria", "")
                if criteria:
                    # Parse CPE string: cpe:2.3:a:vendor:product:version:...
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3] if parts[3] != "*" else ""
                        product = parts[4] if parts[4] != "*" else ""
                        version = parts[5] if len(parts) > 5 and parts[5] != "*" else "N/A"
                        name = f"{vendor} {product}".strip() if vendor else product
                        if name:
                            products.append(f"{name}:{version}")
    return products


def extract_osv_affected_products(details: dict) -> List[str]:
    """Extract affected products from OSV format."""
    affected = details.get("affected", [])
    products = []
    for item in affected:
        package = item.get("package", {})
        ecosystem = package.get("ecosystem", "")
        name = package.get("name", "")
        ranges = item.get("ranges", [])
        versions = []
        for range_item in ranges:
            events = range_item.get("events", [])
            for event in events:
                introduced = event.get("introduced")
                fixed = event.get("fixed")
                if introduced and fixed:
                    versions.append(f"{introduced}..<{fixed}")
                elif fixed:
                    versions.append(f"<{fixed}")
        version_text = ", ".join(versions) if versions else "N/A"
        full_name = f"{ecosystem}/{name}" if ecosystem else name
        if full_name:
            products.append(f"{full_name}:{version_text}")
    return products


def extract_circl_affected_products(details: dict) -> List[str]:
    """Extract affected products from CIRCL format."""
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


def extract_cveorg_affected_products(details: dict) -> List[str]:
    """Extract affected products from CVE.org (MITRE) format."""
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
    return products


def extract_affected_products(details: dict) -> List[str]:
    """Extract affected products from merged data."""
    # Use merged affected products if available
    if "_affected_products" in details:
        return details["_affected_products"]
    # Fallback to old format for backward compatibility
    return []


def get_nvd_details(cve_id: str) -> dict:
    """Fetch CVE details from NVD API."""
    if not cve_id:
        return {}
    url = NVD_URL_TEMPLATE.format(cve_id=cve_id)
    payload = fetch_json(url) or {}
    # NVD returns data in vulnerabilities array
    if payload.get("vulnerabilities"):
        return payload["vulnerabilities"][0].get("cve", {})
    return {}


def get_osv_details(cve_id: str) -> dict:
    """Fetch CVE details from OSV API."""
    if not cve_id:
        return {}
    url = OSV_URL_TEMPLATE.format(cve_id=cve_id)
    return fetch_json(url) or {}


def get_cveorg_details(cve_id: str) -> dict:
    """Fetch CVE details from CVE.org (MITRE) API."""
    if not cve_id:
        return {}
    url = CVEORG_URL_TEMPLATE.format(cve_id=cve_id)
    payload = fetch_json(url) or {}
    # CVE.org returns data in cveMetadata and containers
    return payload


def fetch_all_sources(cve_id: str) -> Dict[str, dict]:
    """Fetch CVE details from all sources in parallel."""
    if not cve_id:
        return {}
    
    sources = {
        "circl": lambda: get_circl_details_direct(cve_id),
        "nvd": lambda: get_nvd_details(cve_id),
        "osv": lambda: get_osv_details(cve_id),
        "cveorg": lambda: get_cveorg_details(cve_id),
    }
    
    results = {}
    # Use ThreadPoolExecutor for parallel requests
    with ThreadPoolExecutor(max_workers=4) as executor:
        future_to_source = {
            executor.submit(fetch_func): source_name
            for source_name, fetch_func in sources.items()
        }
        
        for future in as_completed(future_to_source):
            source_name = future_to_source[future]
            try:
                data = future.result()
                if data and isinstance(data, dict):
                    # Check if data is valid (has some content)
                    if data.get("id") or data.get("containers") or data.get("cveMetadata"):
                        results[source_name] = data
            except Exception:
                # Silently ignore errors from individual sources
                pass
    
    return results


def get_circl_details_direct(cve_id: str) -> dict:
    """Fetch CVE details directly from CIRCL API (without cache)."""
    if not cve_id:
        return {}
    url = CIRCL_URL_TEMPLATE.format(cve_id=cve_id)
    return fetch_json(url) or {}


def merge_cve_data(sources_data: Dict[str, dict]) -> dict:
    """Merge CVE data from multiple sources based on priority."""
    if not sources_data:
        return {}
    
    # Sort sources by priority (higher priority first)
    sorted_sources = sorted(
        sources_data.items(),
        key=lambda x: SOURCE_PRIORITY.get(x[0], 0),
        reverse=True
    )
    
    merged = {}
    
    # Extract and merge CVSS scores (take highest priority available)
    for source_name, data in sorted_sources:
        if not merged.get("_cvss"):
            cvss = None
            if source_name == "circl":
                cvss = extract_circl_cvss(data)
            elif source_name == "nvd":
                cvss = extract_nvd_cvss(data)
            elif source_name == "osv":
                cvss = extract_osv_cvss(data)
            elif source_name == "cveorg":
                cvss = extract_cveorg_cvss(data)
            
            if cvss is not None:
                merged["_cvss"] = cvss
                merged["_cvss_source"] = source_name
    
    # Extract and merge summaries (take highest priority available)
    for source_name, data in sorted_sources:
        if not merged.get("_summary"):
            summary = ""
            if source_name == "circl":
                summary = extract_circl_summary(data)
            elif source_name == "nvd":
                summary = extract_nvd_summary(data)
            elif source_name == "osv":
                summary = extract_osv_summary(data)
            elif source_name == "cveorg":
                summary = extract_cveorg_summary(data)
            
            if summary:
                merged["_summary"] = summary
                merged["_summary_source"] = source_name
    
    # Extract and merge CWE (take highest priority available)
    for source_name, data in sorted_sources:
        if not merged.get("_cwe"):
            cwe = ""
            if source_name == "circl":
                cwe = extract_circl_cwe(data)
            elif source_name == "nvd":
                cwe = extract_nvd_cwe(data)
            elif source_name == "osv":
                cwe = extract_osv_cwe(data)
            elif source_name == "cveorg":
                cwe = extract_cveorg_cwe(data)
            
            if cwe:
                merged["_cwe"] = cwe
                merged["_cwe_source"] = source_name
    
    # Merge references (combine from all sources, remove duplicates)
    all_references = []
    for source_name, data in sorted_sources:
        refs = []
        if source_name == "circl":
            refs = extract_circl_references(data)
        elif source_name == "nvd":
            refs = extract_nvd_references(data)
        elif source_name == "osv":
            refs = extract_osv_references(data)
        elif source_name == "cveorg":
            refs = extract_cveorg_references(data)
        
        for ref in refs:
            if ref and ref not in all_references:
                all_references.append(ref)
    merged["_references"] = all_references
    
    # Merge affected products (combine from all sources, remove duplicates)
    all_products = []
    seen_products = set()
    for source_name, data in sorted_sources:
        products = []
        if source_name == "circl":
            products = extract_circl_affected_products(data)
        elif source_name == "nvd":
            products = extract_nvd_affected_products(data)
        elif source_name == "osv":
            products = extract_osv_affected_products(data)
        elif source_name == "cveorg":
            products = extract_cveorg_affected_products(data)
        
        for product in products:
            if product and product not in seen_products:
                all_products.append(product)
                seen_products.add(product)
    merged["_affected_products"] = all_products
    
    # Extract published date (take highest priority available)
    for source_name, data in sorted_sources:
        if not merged.get("_published"):
            published = None
            if source_name == "circl":
                published = data.get("Published") or data.get("cveMetadata", {}).get("datePublished")
            elif source_name == "nvd":
                published = data.get("cveMetadata", {}).get("datePublished")
            elif source_name == "osv":
                published = data.get("published")
            elif source_name == "cveorg":
                published = data.get("cveMetadata", {}).get("datePublished")
            
            if published:
                merged["_published"] = published
                merged["_published_source"] = source_name
    
    # Store all source data for reference
    merged["_sources"] = sources_data
    merged["_sources_list"] = list(sources_data.keys())
    
    return merged


def get_circl_details(cve_id: str, cache: dict) -> dict:
    """Fetch CVE details from all sources in parallel and merge them."""
    if not cve_id:
        return {}
    if cve_id in cache:
        return cache[cve_id]
    
    # Fetch from all sources in parallel
    sources_data = fetch_all_sources(cve_id)
    
    # Merge data based on priority
    merged_data = merge_cve_data(sources_data)
    
    cache[cve_id] = merged_data
    return merged_data


def get_item_cvss(item: CveItem, circl_cache: dict) -> Optional[float]:
    description_clean = clean_html(item.description) if item.description else ""
    fields = parse_fields(description_clean)
    cve_id = fields["cve_id"] or extract_cve_id(item.title)
    details = get_circl_details(cve_id, circl_cache)
    cvss = extract_cvss(details) or fields["cvss_score"]
    return cvss_to_float(cvss)
