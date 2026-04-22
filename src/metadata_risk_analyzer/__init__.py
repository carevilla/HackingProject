"""Metadata Risk Analyzer package."""

__all__ = ["analyze_image"]


def analyze_image(image_path):
    from .analyzer import analyze_image as _analyze_image

    return _analyze_image(image_path)
