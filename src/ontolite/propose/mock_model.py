"""Deterministic stand-in for a model: returns canned text (including hostile text) for tests."""

from __future__ import annotations


class MockModel:
    def __init__(self, response: str) -> None:
        self.response = response
        self.calls: list[str] = []

    def __call__(self, prompt: str) -> str:
        self.calls.append(prompt)
        return self.response
