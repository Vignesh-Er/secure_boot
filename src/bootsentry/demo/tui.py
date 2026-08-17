"""Rich Terminal User Interface (TUI) for BootSentry live demonstrations."""

from __future__ import annotations

import argparse
import sys
import time
from typing import Any

from rich.align import Align
from rich.box import ROUNDED
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from bootsentry.demo.safe_replay import SAFE_DEMO_SCENARIOS

console = Console()


def render_bootsentry_dashboard(scenario_data: dict[str, Any]) -> None:
    """Render the full Rich 4-panel dashboard for a boot scenario."""
    title = scenario_data.get("title", "BootSentry Verification")
    description = scenario_data.get("description", "")
    stages = scenario_data.get("stages", [])
    g1 = scenario_data.get("gate1_crypto", {})
    g2 = scenario_data.get("gate2_measure", {})
    g3 = scenario_data.get("gate3_behavior", {})
    pcrs = scenario_data.get("pcrs", {})
    verdict = scenario_data.get("verdict", "PASS")
    reason = scenario_data.get("reason", "")
    attestation = scenario_data.get("attestation", "TRUSTED")
    attributions = scenario_data.get("attributions", [])

    # 1. Header Banner
    header_text = Text.from_markup(
        f"[bold cyan]BOOTSENTRY[/bold cyan] [white]-- Post-Quantum AI Secure Boot & Integrity Verification[/white]\n"
        f"[dim]Scenario: [bold yellow]{title}[/bold yellow] | {description}[/dim]"
    )
    header_panel = Panel(header_text, style="blue", box=ROUNDED)

    # 2. Left Panel: Boot Ladder
    ladder_table = Table(box=ROUNDED, expand=True, title="[bold white]Stage Execution Ladder[/bold white]")
    ladder_table.add_column("Stage", style="bold cyan", width=6)
    ladder_table.add_column("Name", width=14)
    ladder_table.add_column("Status", justify="center", width=8)
    ladder_table.add_column("Latency", justify="right", width=9)
    ladder_table.add_column("Verification & Workload Details", style="dim")

    for st in stages:
        status_str = st.get("status", "OK")
        if status_str == "OK":
            badge = "[bold green][OK][/bold green]"
        elif status_str == "WARN":
            badge = "[bold yellow][WARN][/bold yellow]"
        else:
            badge = "[bold red][HALT][/bold red]"

        t_ms = st.get("time_ms", 0.0)
        time_str = f"{t_ms:5.1f} ms" if t_ms > 0 else "  --  "
        ladder_table.add_row(st.get("id", ""), st.get("name", ""), badge, time_str, st.get("detail", ""))

    ladder_panel = Panel(ladder_table, box=ROUNDED, style="cyan")

    # 3. Center Panel: Three Security Gates
    gates_table = Table(box=ROUNDED, expand=True, title="[bold white]Three Security Gates[/bold white]")
    gates_table.add_column("Gate", style="bold white", width=18)
    gates_table.add_column("Mechanism", width=22)
    gates_table.add_column("Status", justify="center", width=10)
    gates_table.add_column("Evaluation Detail", style="dim")

    # Gate 1
    g1_stat = g1.get("status", "PASS")
    g1_badge = "[bold green]PASS[/bold green]" if g1_stat == "PASS" else "[bold red]HALT[/bold red]"
    gates_table.add_row("Gate 1: Cryptography", "NIST ML-DSA-65 (PQC)", g1_badge, g1.get("detail", ""))

    # Gate 2
    g2_stat = g2.get("status", "PASS")
    g2_badge = "[bold green]PASS[/bold green]" if g2_stat == "PASS" else "[bold red]HALT[/bold red]"
    gates_table.add_row("Gate 2: Measurement", "TPM PCR[0..3] + Log", g2_badge, g2.get("detail", ""))

    # Gate 3
    g3_stat = g3.get("status", "PASS")
    if g3_stat == "PASS":
        g3_badge = "[bold green]CLEAN[/bold green]"
    elif g3_stat == "ANOMALY":
        g3_badge = "[bold yellow]ANOMALY[/bold yellow]"
    elif g3_stat == "RULE_FAIL":
        g3_badge = "[bold red]RULE HALT[/bold red]"
    else:
        g3_badge = "[bold red]HALTED[/bold red]"

    gates_table.add_row("Gate 3: AI Behavior", "IF + Markov + EWMA", g3_badge, g3.get("detail", ""))

    gates_panel = Panel(gates_table, box=ROUNDED, style="magenta")

    # 4. Right Panel: PCR State Snapshots
    pcr_table = Table(box=ROUNDED, expand=True, title="[bold white]TPM PCR Bank Snapshot[/bold white]")
    pcr_table.add_column("Register", style="bold cyan", width=8)
    pcr_table.add_column("SHA-256 Digest (Prefix)", style="white")

    for k, v in pcrs.items():
        prefix = f"{v[:16]}...{v[-8:]}" if len(v) >= 24 else v
        pcr_table.add_row(k, prefix)

    pcr_panel = Panel(pcr_table, box=ROUNDED, style="green")

    # 5. Bottom Panel: Verdict & Attribution
    if verdict == "PASS":
        verdict_badge = "[bold white on dark_green] VERDICT: PASS [/bold white on dark_green]"
        v_border = "green"
    elif verdict == "WARN" or "WARN" in verdict:
        verdict_badge = "[bold white on dark_goldenrod] VERDICT: WARN + REDUCED TRUST [/bold white on dark_goldenrod]"
        v_border = "yellow"
    else:
        verdict_badge = "[bold white on dark_red] VERDICT: HALT (SYSTEM BLOCKED) [/bold white on dark_red]"
        v_border = "red"

    attr_lines = []
    if attributions:
        attr_lines.append("[bold yellow]Top Contributing Feature Deviations (Robust Median/MAD z-score):[/bold yellow]")
        for a in attributions:
            f_name = a.get("feature", "")
            obs = a.get("observed", "")
            base = a.get("baseline", "")
            sig = a.get("sigma", "")
            attr_lines.append(f"  * [bold white]{f_name:<24}[/bold white] observed=[cyan]{obs:<10}[/cyan] normal_ref=[dim]{base:<10}[/dim] deviation=[bold magenta]{sig:>8}[/bold magenta]")

    attestation_line = f"[bold white]Attestation State:[/bold white] [bold cyan]{attestation}[/bold cyan]"
    reason_line = f"[bold white]Decision Rationale:[/bold white] {reason}"

    summary_group = Group(
        Align.center(Text.from_markup(f"\n{verdict_badge}\n")),
        Text.from_markup(attestation_line),
        Text.from_markup(reason_line),
        Text.from_markup("\n" + "\n".join(attr_lines) if attr_lines else ""),
    )

    verdict_panel = Panel(summary_group, title="[bold white]Final Policy Engine Decision & Attribution[/bold white]", box=ROUNDED, style=v_border)

    # Print dashboard elements cleanly
    console.print(header_panel)
    console.print(ladder_panel)
    console.print(gates_panel)
    console.print(pcr_panel)
    console.print(verdict_panel)
    console.print("=" * 90 + "\n")


def run_interactive_demo(safe_replay: bool = True) -> None:
    """Run full 7-part hackathon demo suite."""
    scenario_order = [
        "clean",
        "byte_tamper",
        "a1_downgrade",
        "a2_toctou",
        "a3_reorder",
        "a4_drift",
        "benign_load",
        "a5_cross_sku",
    ]

    console.print("\n" + "=" * 90)
    console.print("[bold cyan]      BOOTSENTRY: AI-ASSISTED SECURE BOOT LIVE DEMONSTRATOR[/bold cyan]")
    mode_str = "[bold yellow]SAFE REPLAY MODE[/bold yellow] (Deterministic Validated Artifacts)" if safe_replay else "[bold green]LIVE EXECUTION MODE[/bold green]"
    console.print(f"      Execution Mode: {mode_str}")
    console.print("=" * 90 + "\n")

    for idx, sc_key in enumerate(scenario_order, start=1):
        console.print(f"[bold white][Step {idx}/{len(scenario_order)}][/bold white] Running scenario: [bold cyan]{sc_key}[/bold cyan]...")
        sc_data = SAFE_DEMO_SCENARIOS.get(sc_key, {})
        render_bootsentry_dashboard(sc_data)
        time.sleep(0.5)


def main() -> None:
    parser = argparse.ArgumentParser(description="BootSentry Rich TUI Demonstration")
    parser.add_argument("--scenario", type=str, default=None, help="Run specific scenario (clean, a1_downgrade, a2_toctou, a3_reorder, a4_drift, a5_cross_sku, benign_load)")
    parser.add_argument("--safe-replay", action="store_true", default=True, help="Replay validated artifacts (demo-safe)")
    parser.add_argument("--interactive", action="store_true", help="Run interactive multi-scenario presentation")
    args = parser.parse_args()

    if args.scenario:
        sc_data = SAFE_DEMO_SCENARIOS.get(args.scenario)
        if not sc_data:
            console.print(f"[red]Error: Scenario '{args.scenario}' not found. Available: {list(SAFE_DEMO_SCENARIOS.keys())}[/red]")
            sys.exit(1)
        render_bootsentry_dashboard(sc_data)
    else:
        run_interactive_demo(safe_replay=args.safe_replay)


if __name__ == "__main__":
    main()
