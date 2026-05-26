import datetime
import os

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

from src.ports.services import IReportGenerator


class PdfReportGenerator(IReportGenerator):
    def generate_pdf(self, report_text: str, output_path: str) -> None:
        doc = SimpleDocTemplate(
            output_path, pagesize=A4,
            rightMargin=15*mm, leftMargin=15*mm,
            topMargin=15*mm, bottomMargin=15*mm,
        )
        styles = getSampleStyleSheet()
        story = []

        title_style = ParagraphStyle(
            'Title', parent=styles['Heading1'], fontSize=18, spaceAfter=6*mm,
        )
        story.append(Paragraph("Informe de Seguridad del Proyecto", title_style))
        story.append(Spacer(1, 3*mm))
        story.append(Paragraph(
            f"Generado el {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}",
            styles['Normal'],
        ))
        story.append(Spacer(1, 5*mm))

        detail_style = ParagraphStyle(
            'Detail', fontName='Helvetica', fontSize=9, leading=13, leftIndent=10*mm,
        )

        parts = report_text.split("=" * 60)
        for part in parts:
            if not part.strip():
                continue
            split_lines = part.strip().splitlines()
            if not split_lines:
                continue

            story.append(Paragraph(f"<b>{split_lines[0].strip()}</b>", styles['Heading2']))

            content_lines = split_lines[1:]
            i = 0
            while i < len(content_lines):
                line = content_lines[i].strip()
                if not line:
                    i += 1
                    continue

                if line.startswith("Título:") or line.startswith("Titulo:"):
                    story.append(Paragraph(f"<b>{line}</b>", styles['Normal']))
                    i += 1
                    bullet_lines = []
                    while i < len(content_lines) and (
                        content_lines[i].strip().startswith("•")
                        or content_lines[i].strip().startswith("*")
                    ):
                        bullet_lines.append(content_lines[i].strip())
                        i += 1
                    if bullet_lines:
                        story.append(Paragraph("<br/>".join(bullet_lines), detail_style))
                    story.append(Spacer(1, 2*mm))
                else:
                    story.append(Paragraph(line, styles['Normal']))
                    i += 1

            story.append(Spacer(1, 4*mm))

        doc.build(story)

    def generate_txt(self, report_text: str, output_path: str) -> None:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_text)
