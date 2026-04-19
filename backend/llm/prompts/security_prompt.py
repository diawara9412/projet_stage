def build_security_prompt(context: dict) -> str:
    return (
        "Generate structured security rules from network context. "
        f"Context: {context}"
    )
