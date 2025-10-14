def main() -> None:
    """Legacy main function - use seed-watermark CLI instead."""
    from .cli import main as cli_main
    cli_main()
