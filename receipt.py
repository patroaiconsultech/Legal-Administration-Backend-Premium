from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm

def build_receipt(data: dict) -> bytes:
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    y = h - 25*mm
    c.setFont("Helvetica-Bold", 15)
    c.drawString(20*mm, y, "COMPROVANTE DE ACEITE ELETRÔNICO")
    y -= 12*mm
    c.setFont("Helvetica", 9)
    lines = [
        ("Aceite nº", data["acceptance_id"]),
        ("Projeto", "Estevez Guarda"),
        ("Documento", "Termo de Confidencialidade e Condições de Acesso"),
        ("Versão", data["term_version"]),
        ("Hash SHA-256", data["term_sha256"]),
        ("Destinatário", data["recipient_name"]),
        ("E-mail validado", data["recipient_email"]),
        ("Organização", data["organization"]),
        ("Cargo/Função", data["role"]),
        ("Forma de vinculação", data["representation_mode"]),
        ("Autenticação", "EMAIL_OTP"),
        ("Data/hora UTC", data["accepted_at"]),
        ("Timezone declarado", data["timezone"]),
        ("Identificador da evidência", data["evidence_id"]),
    ]
    for label, value in lines:
        c.setFont("Helvetica-Bold", 8.5)
        c.drawString(20*mm, y, f"{label}:")
        c.setFont("Helvetica", 8.5)
        text = str(value)
        # simple wrapping
        max_chars = 88
        chunks = [text[i:i+max_chars] for i in range(0, len(text), max_chars)] or [""]
        c.drawString(55*mm, y, chunks[0])
        for extra in chunks[1:]:
            y -= 5*mm
            c.drawString(55*mm, y, extra)
        y -= 6.5*mm
        if y < 25*mm:
            c.showPage()
            y = h - 25*mm
    y -= 6*mm
    c.setFont("Helvetica", 8)
    c.drawString(20*mm, y, "Este comprovante registra o evento eletrônico e sua vinculação à versão identificada acima.")
    c.save()
    return buf.getvalue()
