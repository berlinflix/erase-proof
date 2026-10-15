"""Portable PDF summaries with attached signed JSON and offline QR references."""
from html import escape
import io
import json
from pathlib import Path

from .evidence import canonical, verify_record
from .models import EraseProofError

ATTACHMENT = "eraseproof-signed-record.json"


def qr_payload(record):
    return json.dumps({"schema": "eraseproof.record-link.v1", "id": record["payload"]["id"],
                       "payload_sha256": record["payload_sha256"], "signer_fingerprint": record["signer_fingerprint"]}, separators=(",", ":"))


def render(record, destination):
    if not verify_record(record) or not record["payload"].get("verification", {}).get("passed"):
        raise EraseProofError("Only intact signed records with successful scoped verification can be rendered.")
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
    from pypdf import PdfReader, PdfWriter
    import qrcode

    fonts = Path(__file__).parent/"resources"/"fonts"
    for name, filename in (("EP", "DejaVuSans.ttf"), ("EPMono", "DejaVuSansMono.ttf")):
        if name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(name, str(fonts/filename)))
    ink, muted, green = colors.HexColor("#243c32"), colors.HexColor("#61736b"), colors.HexColor("#226446")
    styles = {
        "title": ParagraphStyle("title", fontName="EP", fontSize=28, leading=34, textColor=ink, spaceAfter=12),
        "heading": ParagraphStyle("heading", fontName="EP", fontSize=13, leading=19, textColor=green, spaceBefore=16, spaceAfter=9),
        "body": ParagraphStyle("body", fontName="EP", fontSize=9, leading=14, textColor=ink, spaceAfter=8),
        "small": ParagraphStyle("small", fontName="EP", fontSize=7.7, leading=11.5, textColor=muted, spaceAfter=6),
        "mono": ParagraphStyle("mono", fontName="EPMono", fontSize=7.3, leading=11, textColor=ink, wordWrap="CJK", spaceAfter=5),
    }
    def p(value, style="body"):
        return Paragraph(escape(str(value)).replace("\n", "<br/>"), styles[style])
    payload, verification = record["payload"], record["payload"]["verification"]
    target, plan = payload["target"], payload.get("plan", {})
    operation = payload.get("operation", plan.get("method", "logical overwrite"))
    # Keep rows independent: long paths and scope text can flow without clipping.
    def rows(values):
        table = Table([[p(key, "small"), p(value)] for key, value in values], colWidths=[116, 395], hAlign="LEFT")
        table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                   ("RIGHTPADDING", (0, 0), (-1, -1), 12), ("TOPPADDING", (0, 0), (-1, -1), 6),
                                   ("BOTTOMPADDING", (0, 0), (-1, -1), 6), ("LINEBELOW", (0, 0), (-1, -1), .4, colors.HexColor("#dce5dd"))]))
        return table

    story = [Spacer(1, 20), p("Verification record", "title"),
             p("VERIFIED WITHIN THE RECORDED LOGICAL SCOPE", "heading"),
             p("This report summarizes measured results. The attached Ed25519-signed JSON is the authoritative record; this PDF wrapper is not digitally signed.", "body"),
             rows([("RECORD ID", payload["id"]), ("ISSUED UTC", payload["issued_at"]),
                   ("TARGET", target["path"]), ("MODEL / SERIAL", f"{target.get('model', target['kind'])} / {target.get('serial', 'not applicable')}"),
                   ("OPERATION", operation), ("BYTES CHECKED", f"{verification.get('bytes_checked', 0):,}"),
                   ("REFERENCE SCORE", "Unavailable - no complete reference baseline" if verification.get("rrs") is None else f"{verification['rrs']:.6f} (provided reference set only)")]),
             p("What this result establishes", "heading"), p(verification.get("scope", payload.get("assurance", "Scope stated in the attached record."))),
             p("Assurance boundary", "heading"), p(payload.get("assurance", "No physical-media or compliance assurance is established.")),
             p("A zero reference score does not establish destruction of unknown copies. VM snapshots, backups, host storage and flash translation layers require separate evaluation.", "small"),
             PageBreak(), Spacer(1, 20), p("Evidence & verification", "title"),
             p("Ed25519 signature: VALID", "heading"), p("The embedded operator key proves integrity. Confirm its full fingerprint through a separately trusted channel before accepting operator identity."),
             p("SIGNER FINGERPRINT (SHA-256)", "small"), p(record["signer_fingerprint"], "mono"),
             p("SIGNED PAYLOAD SHA-256", "small"), p(record["payload_sha256"], "mono"),
             p("PREVIOUS AUDIT HEAD", "small"), p(payload.get("previous_audit_hash", "Unavailable"), "mono"),
             p("Measured checks", "heading")]
    checks = []
    for name in ("nonzero_bytes", "reference_count", "matched_reference_blocks", "metadata_residues", "all_filesystem_copies_verified"):
        if name in verification:
            value = verification[name]
            checks.append((name.replace("_", " ").capitalize(), json.dumps(value) if isinstance(value, (dict, list)) else str(value)))
    if "carved_candidates" in verification:
        checks.append(("Supported carved candidates", len(verification["carved_candidates"])))
    if "sha256" in verification:
        checks.append(("Full read-back SHA-256", verification["sha256"]))
    story.append(rows(checks or [("Scoped verification", "Passed; see attached measurements")]))
    story.extend([p("Offline verification", "heading"),
                  p("The QR code identifies the record hash and signer fingerprint; it is a reference, not an independent signature. Verify the attached JSON with EraseProof and a trusted fingerprint."),
                  p("EraseProof --cli pdf-record report.pdf --trusted-fingerprint EXPECTED_SHA256", "mono")])
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=4, border=4)
    qr.add_data(qr_payload(record))
    qr.make(fit=True)
    png = io.BytesIO()
    qr.make_image(fill_color="black", back_color="white").save(png, format="PNG")
    png.seek(0)
    story.append(Table([[Image(png, width=133, height=133), p("Keep the signed JSON and an independently stored audit checkpoint. A local chain cannot detect replacement of its entire history without an external anchor.\n\nNo NIST/IEEE compliance claim is made by this report.", "small")]], colWidths=[155, 356]))

    buffer = io.BytesIO()
    def page(canvas, document):
        width, height = A4
        canvas.saveState()
        canvas.setFillColor(green)
        canvas.rect(0, height-10, width, 10, stroke=0, fill=1)
        canvas.setFont("EP", 9)
        canvas.drawString(42, height-35, "E_  EraseProof")
        canvas.setFillColor(muted)
        canvas.setFont("EP", 7)
        canvas.drawString(42, 27, payload["id"])
        canvas.drawRightString(width-42, 27, f"Page {document.page}")
        canvas.restoreState()
    document = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=42, rightMargin=42, topMargin=52, bottomMargin=49,
                                 title="EraseProof verification record", author="EraseProof local operator")
    document.build(story, onFirstPage=page, onLaterPages=page)
    buffer.seek(0)
    writer = PdfWriter(clone_from=PdfReader(buffer))
    writer.add_attachment(ATTACHMENT, canonical(record))
    destination = Path(destination).expanduser().resolve()
    with destination.open("xb") as file:
        writer.write(file)
    return {"path": str(destination), "pages": len(writer.pages), "attachment": ATTACHMENT, "payload_sha256": record["payload_sha256"]}


def attached_record(path):
    from pypdf import PdfReader
    if Path(path).stat().st_size > 32*1024*1024:
        raise EraseProofError("PDF record exceeds 32 MiB.")
    reader = PdfReader(path, strict=True)
    if reader.is_encrypted:
        raise EraseProofError("Encrypted PDF records are not supported.")
    values = reader.attachments.get(ATTACHMENT, [])
    if len(values) != 1 or len(values[0]) > 8*1024*1024:
        raise EraseProofError("Expected one bounded signed JSON attachment.")
    return json.loads(values[0])
