def multiply_ip(url):
    parts = url.strip(".").split(".")

    if "multiply" not in parts:
        return None

    index = parts.index("multiply")
    result = 1

    for part in parts[:index]:
        result *= int(part)

    return f"127.0.0.{result % 256}"