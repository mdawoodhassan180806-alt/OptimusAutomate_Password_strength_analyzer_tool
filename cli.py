#!/usr/bin/env python3
"""
Password Strength Analyzer — CLI

Usage:
    python cli.py                 Interactive mode (prompts you, hides input)
    python cli.py "MyP@ssw0rd"    Analyze a single password given as an argument
    python cli.py --file list.txt Analyze every password in a file, one per line
"""

import sys
import getpass
import argparse

from analyzer import analyze_password

BAR_WIDTH = 30
COLORS = {
    0: "\033[91m",  # red
    1: "\033[91m",  # red
    2: "\033[93m",  # yellow
    3: "\033[92m",  # green
    4: "\033[92m",  # green
}
RESET = "\033[0m"
BOLD = "\033[1m"


def supports_color() -> bool:
    return sys.stdout.isatty()


def render_bar(score: int) -> str:
    filled = int(BAR_WIDTH * (score + 1) / 5)
    bar = "█" * filled + "░" * (BAR_WIDTH - filled)
    if supports_color():
        return f"{COLORS[score]}{bar}{RESET}"
    return bar


def print_report(password: str, result: dict, show_password: bool = False) -> None:
    label = result["label"]
    color = COLORS.get(result["score"], "") if supports_color() else ""
    reset = RESET if supports_color() else ""
    bold = BOLD if supports_color() else ""

    shown = password if show_password else ("*" * len(password) or "(empty)")
    print(f"\n{bold}Password:{reset} {shown}")
    print(f"{bold}Strength:{reset} {color}{label}{reset}  [{render_bar(result['score'])}]")
    print(f"{bold}Estimated entropy:{reset} {result['entropy_bits']} bits")
    print(f"{bold}Estimated offline crack time:{reset} {result['crack_time']}")

    if result["is_common"]:
        print(f"{color}⚠ This password appears in a common-password list.{reset}")

    print(f"\n{bold}Issues found:{reset}")
    for issue in result["issues"]:
        print(f"  - {issue}")

    if result["suggestions"]:
        print(f"\n{bold}Suggestions:{reset}")
        for suggestion in result["suggestions"]:
            print(f"  - {suggestion}")
    print()


def interactive_mode() -> None:
    print("=== Password Strength Analyzer ===")
    print("Type a password to analyze it, or press Ctrl+C / type 'quit' to exit.")
    print("(Input is hidden as you type.)\n")
    while True:
        try:
            pw = getpass.getpass("Password: ")
        except (KeyboardInterrupt, EOFError):
            print("\nGoodbye.")
            break
        if pw.strip().lower() == "quit":
            print("Goodbye.")
            break
        result = analyze_password(pw)
        print_report(pw, result, show_password=False)


def file_mode(path: str) -> None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [line.rstrip("\n") for line in f if line.strip()]
    except OSError as e:
        print(f"Error reading file '{path}': {e}")
        sys.exit(1)

    print(f"Analyzing {len(lines)} password(s) from {path}\n")
    for pw in lines:
        result = analyze_password(pw)
        print_report(pw, result, show_password=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze password strength.")
    parser.add_argument("password", nargs="?", help="Password to analyze directly (visible in shell history — use with care).")
    parser.add_argument("--file", help="Path to a text file with one password per line.")
    args = parser.parse_args()

    if args.file:
        file_mode(args.file)
    elif args.password is not None:
        result = analyze_password(args.password)
        print_report(args.password, result, show_password=True)
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
