from io import BytesIO


def build_text_report(payload: dict) -> str:
    return "\n".join(f"{k}: {v}" for k, v in payload.items())


def build_pdf_report(payload: dict) -> bytes:
    buffer = BytesIO()
    text = build_text_report(payload).encode("utf-8")
    buffer.write(text)
    return buffer.getvalue()
