def require_keys(data: dict, keys: list[str]) -> None:
    missing = [key for key in keys if key not in data]
    if missing:
        raise ValueError(f"Missing keys: {', '.join(missing)}")
