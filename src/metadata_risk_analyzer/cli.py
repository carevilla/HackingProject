from __future__ import annotations

import argparse
from pathlib import Path

from .analyzer import analyze_image
from .reporting import render_json_report, render_text_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="metadata-risk-analyzer",
        description="Analyze image metadata and score privacy risk.",
    )
    parser.add_argument("images", nargs="+", help="Path(s) to image files.")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON instead of a text report.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    exit_code = 0
    for index, image_arg in enumerate(args.images):
        try:
            report = analyze_image(Path(image_arg))
        except FileNotFoundError:
            print(f"File not found: {image_arg}")
            exit_code = 1
            continue
        except OSError as exc:
            print(f"Could not analyze {image_arg}: {exc}")
            exit_code = 1
            continue

        output = render_json_report(report) if args.json else render_text_report(report)
        if index:
            print()
        print(output)

    return exit_code
