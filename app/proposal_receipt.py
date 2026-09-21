from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm


def build_proposal_receipt(data: dict) -> bytes:
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    y = h - 24 * mm

    c.setFont("Helvetica-Bold", 14)
    c.drawString(20 * mm, y, "COMPROVANTE DE ACEITE ELETRONICO")
    y -= 8 * mm
    c.setFont("Helvetica-Bold", 10)
    c.drawString(20 * mm, y, "PROPOSTA COMERCIAL — ESTEVEZ GUARDA")
    y -= 10 * mm

    lines = [
        ("Aceite no.", data["acceptance_id"]),
        ("Projeto", "Estevez Guarda"),
        ("Documento", data["proposal_title"]),
        ("Versao da proposta", data["proposal_version"]),
        ("SHA-256 da proposta", data["proposal_sha256"]),
        ("Texto de aceite", data["acceptance_text_version"]),
        ("SHA-256 do texto de aceite", data["acceptance_text_sha256"]),
        ("Destinatario", data["recipient_name"]),
        ("E-mail autenticado", data["recipient_email"]),
        ("Organizacao", data["organization"]),
        ("Cargo/Funcao", data["role"]),
        ("Forma de vinculacao", data["representation_mode"]),
        ("Autenticacao", data["authentication_method"]),
        ("Data/hora UTC", data["accepted_at"]),
        ("Timezone declarado", data["timezone"]),
        ("Identificador da evidencia", data["evidence_id"]),
    ]

    for label, value in lines:
        if y < 26 * mm:
            c.showPage()
            y = h - 24 * mm
        c.setFont("Helvetica-Bold", 8.4)
        c.drawString(20 * mm, y, f"{label}:")
        c.setFont("Helvetica", 8.4)
        text = str(value)
        chunks = [text[i:i + 86] for i in range(0, len(text), 86)] or [""]
        c.drawString(58 * mm, y, chunks[0])
        for extra in chunks[1:]:
            y -= 5 * mm
            c.drawString(58 * mm, y, extra)
        y -= 6.2 * mm

    y -= 3 * mm
    c.setFont("Helvetica", 8)
    c.drawString(
        20 * mm,
        y,
        "Este comprovante registra o aceite eletronico e sua vinculacao a versao e aos hashes acima.",
    )
    c.save()
    return buf.getvalue()
