from datetime import datetime, timezone
import html
from typing import Iterable, List

from config import ALERT_THRESHOLD, RECENT_WINDOW_HOURS, SIREN_THRESHOLD
from cve_feed import (
    CveItem,
    clean_html,
    cvss_to_float,
    extract_circl_affected_products,
    extract_circl_cwe,
    extract_circl_references,
    extract_circl_summary,
    extract_cve_id,
    extract_cveorg_cwe,
    extract_cveorg_references,
    extract_cveorg_summary,
    extract_nvd_cwe,
    extract_nvd_references,
    extract_nvd_summary,
    extract_osv_summary,
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


def pick_summary(sources: dict, rss_fields: dict) -> str:
    circl = sources.get("circl") or {}
    nvd = sources.get("nvd") or {}
    cveorg = sources.get("cveorg") or {}
    osv = sources.get("osv") or {}
    return (
        extract_circl_summary(circl)
        or extract_nvd_summary(nvd)
        or extract_cveorg_summary(cveorg)
        or extract_osv_summary(osv)
        or rss_fields.get("description")
        or "N/A"
    )


def pick_cwe(sources: dict) -> str:
    circl = sources.get("circl") or {}
    nvd = sources.get("nvd") or {}
    cveorg = sources.get("cveorg") or {}
    return extract_circl_cwe(circl) or extract_nvd_cwe(nvd) or extract_cveorg_cwe(cveorg)


def pick_references(sources: dict) -> List[str]:
    circl = sources.get("circl") or {}
    nvd = sources.get("nvd") or {}
    cveorg = sources.get("cveorg") or {}
    return (
        extract_circl_references(circl)
        or extract_nvd_references(nvd)
        or extract_cveorg_references(cveorg)
    )


def render_message(
    item: CveItem,
    sources: dict,
    cvss_score: float | None,
    index: int,
    total: int,
    total_available: int,
    mode: str,
) -> str:
    description_clean = clean_html(item.description) if item.description else ""
    fields = parse_fields(description_clean)
    cve_id = fields["cve_id"] or extract_cve_id(item.title)

    summary = pick_summary(sources, fields)
    cwe = pick_cwe(sources)
    references = pick_references(sources)
    affected_products = extract_circl_affected_products(sources.get("circl") or {})
    published = sources.get("circl", {}).get("Published") or sources.get("cveorg", {}).get(
        "cveMetadata", {}
    ).get("datePublished")

    cvss_value = cvss_to_float(cvss_score)
    if cvss_value is not None and cvss_value > SIREN_THRESHOLD:
        alert = " 🚨🚨🚨"
    elif cvss_value is not None and cvss_value > ALERT_THRESHOLD:
        alert = " ⚠️"
    else:
        alert = ""

    title = html.escape(item.title)
    url = html.escape(item.link or "N/A")
    if mode == "experimental":
        timestamp = datetime.now(timezone.utc).strftime("%b %d, %Y %H:%M UTC")
        if total_available > total:
            header = f"<b>{timestamp} | CVE {index}/{total} (of {total_available})</b>"
        else:
            header = f"<b>{timestamp} | CVE {index}/{total}</b>"
    else:
        header = f"<b>CVE {index}/{total}</b>"

    lines = [
        header,
        "",
        f"<b>Title</b>: {title}",
        f"<b>URL</b>: <a href=\"{url}\">{url}</a>",
        f"<b>CVSS Score</b>: {html.escape(str(cvss_score) if cvss_score else 'N/A')}{alert}",
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
    return "\n".join(lines).strip()


def render_messages(records: list[dict], mode: str, total_available: int) -> List[str]:
    total = len(records)
    return [
        render_message(
            record["item"],
            record["sources"],
            record["cvss_score"],
            index + 1,
            total,
            total_available,
            mode,
        )
        for index, record in enumerate(records)
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


def build_header(count: int, mode: str, total_available: int) -> str:
    report_date = datetime.now(timezone.utc).strftime("%b %d, %Y")
    if mode == "experimental":
        if total_available > count:
            return (
                f"<b>{report_date} (UTC)</b>\n"
                f"New CVEs (experimental): {count} (of {total_available})"
            )
        return f"<b>{report_date} (UTC)</b>\nNew CVEs (experimental): {count}"
    if total_available > count:
        return (
            f"<b>{report_date} (UTC)</b>\n"
            f"Critical CVEs in last {RECENT_WINDOW_HOURS}h: {count} (of {total_available})"
        )
    return (
        f"<b>{report_date} (UTC)</b>\n"
        f"Critical CVEs in last {RECENT_WINDOW_HOURS}h: {count}"
    )
