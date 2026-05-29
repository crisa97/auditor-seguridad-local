import datetime
import html
import logging
import os
import re

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from src.ports.services import IReportGenerator

logger = logging.getLogger(__name__)


def _esc(text: str) -> str:
    return html.escape(text, quote=True)


_SEVERITY_COLORS = {
    "alta": HexColor("#d32f2f"),
    "critical": HexColor("#b71c1c"),
    "media": HexColor("#f57c00"),
    "baja": HexColor("#388e3c"),
    "info": HexColor("#1976d2"),
}


def _severity_color(value: str):
    v = value.strip().lower().rstrip(".")
    for key, color in _SEVERITY_COLORS.items():
        if v.startswith(key):
            return color
    return None


class PdfReportGenerator(IReportGenerator):
    def generate_pdf(self, report_text: str, output_path: str) -> None:
        doc = SimpleDocTemplate(
            output_path, pagesize=A4,
            rightMargin=18*mm, leftMargin=18*mm,
            topMargin=15*mm, bottomMargin=15*mm,
        )
        styles = getSampleStyleSheet()
        story = []

        # ── Title ──
        title_style = ParagraphStyle(
            'ReportTitle', parent=styles['Heading1'],
            fontSize=22, spaceAfter=4*mm, alignment=1,
            textColor=HexColor("#1a237e"),
        )
        story.append(Paragraph("Informe de Seguridad del Proyecto", title_style))
        story.append(Spacer(1, 2*mm))

        # ── Date ──
        date_style = ParagraphStyle('DateLine', fontSize=9, textColor=HexColor("#666666"), alignment=1)
        story.append(Paragraph(
            f"Generado el {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}", date_style))
        story.append(Spacer(1, 4*mm))

        # ── Disclaimer ──
        disclaimer_style = ParagraphStyle(
            'Disclaimer', fontSize=9, leading=13,
            textColor=HexColor("#555555"),
            borderWidth=0.5, borderColor=HexColor("#cccccc"),
            backColor=HexColor("#fafafa"),
            leftIndent=4*mm, rightIndent=4*mm,
        )
        story.append(Paragraph(
            "<b>Aviso importante:</b> Todos los hallazgos identificados se deben "
            "verificar de forma manual, ya que esta es una herramienta automatizada "
            "para evitar falsos positivos. Posteriormente, un auditor real puede "
            "identificar nuevos danos o vulnerabilidades no detectadas.",
            disclaimer_style,
        ))
        story.append(Spacer(1, 6*mm))

        # ── Style constants ──
        field_label_style = ParagraphStyle('FL', fontName='Helvetica-Bold', fontSize=9)
        field_value_style = ParagraphStyle('FV', fontName='Helvetica', fontSize=9, leading=13)
        code_style = ParagraphStyle(
            'Code', fontName='Courier', fontSize=7.5, leading=10,
            leftIndent=6*mm, backColor=HexColor("#f5f5f5"),
            borderWidth=0.5, borderColor=HexColor("#dddddd"),
        )
        intro_style = ParagraphStyle('Intro', fontName='Helvetica', fontSize=9, leading=13)
        finding_style = ParagraphStyle(
            'Finding', fontName='Helvetica-Bold',
            fontSize=11, leading=15, spaceAfter=2*mm,
            textColor=HexColor("#c62828"),
        )

        sections = re.split(r"={5,}", report_text)
        for section in sections:
            section = section.strip()
            if not section:
                continue
            lines = section.splitlines()
            if not lines:
                continue

            # ── File header ──
            file_header = lines[0].strip()
            file_style = ParagraphStyle(
                'FileH', parent=styles['Heading2'],
                fontSize=13, spaceAfter=3*mm, textColor=HexColor("#1a237e"),
            )
            story.append(Paragraph(f"<b>{_esc(file_header)}</b>", file_style))

            i = 1
            while i < len(lines):
                raw = lines[i]
                line = raw.strip()
                i += 1
                if not line:
                    continue

                # ── Code fence ──
                if line.startswith("```"):
                    buf = []
                    while i < len(lines):
                        cl = lines[i]
                        i += 1
                        if cl.strip().startswith("```"):
                            break
                        buf.append(cl)
                    if buf:
                        story.append(Paragraph("<br/>".join(_esc(l) for l in buf), code_style))
                        story.append(Spacer(1, 2*mm))
                    continue

                # ── Finding title: "### Something" or "### N. Something" ──
                if re.match(r"^#{1,4}\s", line):
                    title_text = re.sub(r"^#{1,4}\s+\d*[\.\)]?\s*\*{0,2}", "", line).strip().rstrip("*").strip()
                    if title_text:
                        story.append(Paragraph(f"<b>{_esc(title_text)}</b>", finding_style))
                    continue

                # ── Field: "**Field:** Value" (value may be multiline) ──
                m = re.match(r"^\*{2}(.+?)\*{2}:\s*(.*)", line)
                if m:
                    field_name = m.group(1).strip()
                    first_value = m.group(2).strip()
                    # Accumulate continuation lines until next field or blank line
                    full_value = [first_value] if first_value else []
                    while i < len(lines):
                        nxt = lines[i].strip()
                        if not nxt or nxt.startswith("**") or nxt.startswith("```") or nxt.startswith("#"):
                            break
                        full_value.append(nxt)
                        i += 1
                    value_text = " ".join(full_value)

                    label = Paragraph(f"<b>{_esc(field_name)}:</b>", field_label_style)

                    field_lower = field_name.lower()
                    if "severidad" in field_lower or "severidad" in field_lower:
                        color = _severity_color(value_text)
                        if color:
                            sv = ParagraphStyle('SV', fontName='Helvetica-Bold',
                                                fontSize=10, textColor=color)
                            val = Paragraph(f"<b>{_esc(value_text)}</b>", sv)
                        else:
                            val = Paragraph(_esc(value_text), field_value_style)
                    else:
                        val = Paragraph(_esc(value_text), field_value_style)

                    col_w = doc.width * 0.24
                    tbl = Table([[label, val]], colWidths=[col_w, doc.width - col_w])
                    tbl.setStyle(TableStyle([
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('LEFTPADDING', (0, 0), (-1, -1), 2),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 2),
                        ('TOPPADDING', (0, 0), (-1, -1), 1),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
                    ]))
                    story.append(tbl)
                    continue

                # ── Bullet list ──
                if line.startswith("- ") or line.startswith("* ") or line.startswith("\u2022 "):
                    story.append(Paragraph(f"&bull; {_esc(line[2:])}", field_value_style))
                    continue

                # ── Numbered list ──
                if re.match(r"^\d+[\.\)]\s", line):
                    story.append(Paragraph(_esc(line), field_value_style))
                    continue

                # ── Regular text ──
                story.append(Paragraph(_esc(line), intro_style))

            story.append(Spacer(1, 4*mm))

        try:
            doc.build(story)
        except Exception as e:
            logger.error("Error al generar PDF: %s", e)
            raise

    def generate_txt(self, report_text: str, output_path: str) -> None:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_text)
