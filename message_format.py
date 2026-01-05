from datetime import datetime, timezone
import html
from typing import Iterable, List

from config import ALERT_THRESHOLD, RECENT_WINDOW_HOURS, SIREN_THRESHOLD
from cve_feed import (
    CveItem,
    clean_html,
    cvss_to_float,
    extract_affected_products,
    extract_cwe,
    extract_cvss,
    extract_references,
    extract_summary,
    extract_cve_id,
    get_circl_details,
    get_item_cvss,
    parse_fields,
)


def format_published(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    parsed = parsed.astimezone(timezone.utc)
    return parsed.strftime("%b %d, %Y %H:%M UTC")


def render_message(item: CveItem, circl_cache: dict, index: int, total: int) -> str:
    description_clean = clean_html(item.description) if item.description else ""
    fields = parse_fields(description_clean)
    cve_id = fields["cve_id"] or extract_cve_id(item.title)
    details = get_circl_details(cve_id, circl_cache)
    cvss = extract_cvss(details) or fields["cvss_score"]
    cvss_value = cvss_to_float(cvss)
    summary = extract_summary(details) or fields["description"] or "N/A"
    cwe = extract_cwe(details)
    # Get published date from merged data
    published = details.get("_published")
    if not published:
        # Fallback to old format for backward compatibility
        published = (
            details.get("Published") 
            or details.get("cveMetadata", {}).get("datePublished")
            or details.get("published")
        )
    references = extract_references(details)
    affected_products = extract_affected_products(details)
    
    # Add sources info if available
    sources_list = details.get("_sources_list", [])

    if cvss_value is not None and cvss_value > SIREN_THRESHOLD:
        alert = " 🚨🚨🚨"
    elif cvss_value is not None and cvss_value > ALERT_THRESHOLD:
        alert = " ⚠️"
    else:
        alert = ""

    title = html.escape(item.title)
    url = html.escape(item.link or "N/A")
    lines = [
        f"<b>CVE {index}/{total}</b>",
        "",
        f"<b>Title</b>: {title}",
        f"<b>URL</b>: <a href=\"{url}\">{url}</a>",
        f"<b>CVSS Score</b>: {html.escape(str(cvss) if cvss else 'N/A')}{alert}",
        f"<b>Description</b>: {html.escape(summary)}",
    ]
    if cwe:
        lines.append(f"<b>CWE</b>: {html.escape(cwe)}")
    if published:
        lines.append(f"<b>Published</b>: {html.escape(format_published(published))}")
    if references:
        lines.append("<b>References</b>:")
        for ref in references[:10]:
            ref_url = html.escape(ref)
            lines.append(f"• <a href=\"{ref_url}\">{ref_url}</a>")
    if affected_products:
        lines.append("<b>Affected Products</b>:")
        for product in affected_products[:10]:
            lines.append(f"• {html.escape(product)}")
    # Add sources info if multiple sources were used
    if sources_list and len(sources_list) > 1:
        sources_str = ", ".join(sources_list).upper()
        lines.append(f"<i>Sources: {html.escape(sources_str)}</i>")
    return "\n".join(lines).strip()


def render_messages(items: Iterable[CveItem], circl_cache: dict) -> List[str]:
    item_list = list(items)
    scored_items = [(get_item_cvss(item, circl_cache) or 0.0, item) for item in item_list]
    scored_items.sort(key=lambda entry: entry[0], reverse=True)
    item_list = [item for _, item in scored_items]
    total = len(item_list)
    return [
        render_message(item, circl_cache, index + 1, total)
        for index, item in enumerate(item_list)
    ]


def split_message(text: str, limit: int) -> List[str]:
    if len(text) <= limit:
        return [text]
    parts: List[str] = []
    while text:
        chunk = text[:limit]
        split_at = chunk.rfind("\n")
        if split_at == -1 or split_at < limit * 0.5:
            split_at = len(chunk)
        parts.append(text[:split_at].rstrip())
        text = text[split_at:].lstrip()
    return parts


def build_header(count: int) -> str:
    report_date = datetime.now(timezone.utc).strftime("%b %d, %Y")
    return (
        f"<b>{report_date} (UTC)</b>\n"
        f"Critical CVEs in last {RECENT_WINDOW_HOURS}h: {count}"
    )
