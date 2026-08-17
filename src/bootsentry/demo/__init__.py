"""Demo subsystem exports."""

from bootsentry.demo.safe_replay import SAFE_DEMO_SCENARIOS
from bootsentry.demo.tui import render_bootsentry_dashboard, run_interactive_demo

__all__ = [
    "SAFE_DEMO_SCENARIOS",
    "render_bootsentry_dashboard",
    "run_interactive_demo",
]
