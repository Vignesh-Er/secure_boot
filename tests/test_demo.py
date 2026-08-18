"""Unit tests for Rich Terminal UI and Safe Replay Mode."""

from bootsentry.demo.safe_replay import SAFE_DEMO_SCENARIOS
from bootsentry.demo.tui import render_bootsentry_dashboard, run_interactive_demo


class TestDemoTUI:
    def test_safe_demo_scenarios_completeness(self):
        expected_scenarios = [
            "clean",
            "byte_tamper",
            "a1_downgrade",
            "a2_toctou",
            "a3_reorder",
            "a4_drift",
            "benign_load",
            "a5_cross_sku",
        ]
        for s in expected_scenarios:
            assert s in SAFE_DEMO_SCENARIOS
            data = SAFE_DEMO_SCENARIOS[s]
            assert "title" in data
            assert "stages" in data
            assert len(data["stages"]) == 4
            assert "gate1_crypto" in data
            assert "gate2_measure" in data
            assert "gate3_behavior" in data
            assert "verdict" in data
            assert "attributions" in data

    def test_render_all_scenarios(self, capsys):
        for _s, data in SAFE_DEMO_SCENARIOS.items():
            render_bootsentry_dashboard(data)
            captured = capsys.readouterr()
            # Assert that dashboard sections and verdict badge were rendered
            assert "VERDICT:" in captured.out or "VERDICT" in captured.out
            assert "TPM PCR Bank Snapshot" in captured.out
            assert "Three Security Gates" in captured.out

    def test_run_interactive_demo_safe(self, capsys):
        run_interactive_demo(safe_replay=True)
        captured = capsys.readouterr()
        assert "BOOTSENTRY: AI-ASSISTED SECURE BOOT LIVE DEMONSTRATOR" in captured.out
        assert "SAFE REPLAY MODE" in captured.out
