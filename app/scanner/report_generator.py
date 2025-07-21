from fpdf import FPDF
import uuid
import os

def generate_pdf_report(scan_data):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Server Security Report", ln=True, align='C')
    pdf.ln(10)

    for key, value in scan_data.items():
        pdf.cell(200, 10, txt=f"{key.upper()}:", ln=True)
        if isinstance(value, list):
            for item in value:
                pdf.cell(200, 10, txt=f"  - {item}", ln=True)
        else:
            pdf.cell(200, 10, txt=str(value), ln=True)
        pdf.ln(5)

    filename = f"report_{uuid.uuid4()}.pdf"
    path = os.path.join("/tmp", filename)
    pdf.output(path)
    return path