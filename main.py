"""
main.py - Single entry point for SecureGuard AI.
Wires all modules together with argparse CLI.

Usage:
  python main.py --scan report.json --repo ./project
  python main.py --scan report.json --repo ./project --interactive
  python main.py --scan report.json --repo ./project --vuln-types sql_injection,xss
"""
import argparse
import json
import os
import sys
import yaml
from typing import List, Dict, Any

from dotenv import load_dotenv

from parser import parse_scan_report
from locator import locate_vulnerability
from fp_filter import filter_false_positives
from agent.agent import run_remediation
from reporter import generate_summary_report
from config.llm_factory import check_api_key, get_provider_name, _load_llm_config


def load_config(config_path: str = None) -> dict:
    """Load vulnerability configuration from YAML file."""
    if config_path is None:
        config_path = os.path.join(os.path.dirname(__file__), "config", "vuln_config.yaml")

    if not os.path.exists(config_path):
        print(f"[Config] No config file found at {config_path}, using defaults.")
        return {"settings": {}, "vulnerabilities": {}}

    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    print(f"[Config] Loaded {len(config.get('vulnerabilities', {}))} vulnerability types from {config_path}")
    return config


def get_enabled_types(config: dict, cli_types: List[str] = None) -> List[str]:
    """Get the list of enabled vulnerability types."""
    if cli_types:
        return cli_types

    vuln_config = config.get("vulnerabilities", {})
    if vuln_config:
        return list(vuln_config.keys())

    # Default: all built-in types
    from prompts.fix_templates import list_supported_types
    return list_supported_types()


def run_pipeline(
    scan_report: str,
    repo_path: str,
    interactive: bool = False,
    config_path: str = None,
    vuln_types: List[str] = None,
    max_retries: int = 3,
    verbose: bool = False,
) -> List[Dict[str, Any]]:
    """
    Run the full SecureGuard AI remediation pipeline.

    Pipeline stages:
    1. Parse - Read scan report
    2. Filter - Remove false positives
    3. Locate - Find vulnerable code context
    4. For each vulnerability:
       a. Agent - Reason + fix (LangGraph workflow)
       b. Validate - Run tests
       c. Review - Optional human approval
       d. Patch - Git diff output
       e. Report - Plain English doc
    """
    # Load configuration
    config = load_config(config_path)
    settings = config.get("settings", {})

    if max_retries is None:
        max_retries = settings.get("max_retries", 3)
    if not interactive:
        interactive = settings.get("interactive_mode", False)
    context_lines = settings.get("context_lines", 20)
    confidence_threshold = settings.get("confidence_threshold", 0.75)

    enabled_types = get_enabled_types(config, vuln_types)

    print("\n" + "=" * 70)
    print("  SECUREGUARD AI - Security Vulnerability Detection & Remediation")
    print("=" * 70)
    print(f"  Scan report  : {scan_report}")
    print(f"  Repository   : {repo_path}")
    print(f"  LLM provider : {get_provider_name(config)}")
    print(f"  Mode         : {'Interactive' if interactive else 'Automatic'}")
    print(f"  Max retries  : {max_retries}")
    print(f"  Vuln types   : {len(enabled_types)} enabled")
    print("=" * 70)

    # ── Stage 1: Parse ──
    print("\n[Stage 1] Parsing scan report...")
    findings = parse_scan_report(scan_report)
    print(f"  Found {len(findings)} vulnerability findings in report")

    if not findings:
        print("  No vulnerabilities found. Exiting.")
        return []

    # ── Pre-filter: keep only enabled vulnerability types ──
    findings = [f for f in findings if f.get('vuln_type') in enabled_types]
    if not findings:
        print(f"  No findings match the enabled vulnerability types: {enabled_types}")
        print("  Enable more types in config/vuln_config.yaml or use --vuln-types flag.")
        return []
    print(f"  {len(findings)} finding(s) match enabled vulnerability types: {enabled_types}")

    # ── Stage 2: Locate ──
    print("\n[Stage 2] Locating vulnerable code...")
    enriched = []
    for f in findings:
        located = locate_vulnerability(f, context_lines=context_lines)
        enriched.append(located)
        if located.get('locator_error'):
            print(f"  ⚠️  {located['vuln_type']}: {located['locator_error']}")
        else:
            print(f"  ✅ {located['vuln_type']} at {located['file_path']}:{located['line_number']}")

    # ── Stage 3: Filter false positives ──
    print("\n[Stage 3] Filtering false positives...")
    filtered = filter_false_positives(
        enriched,
        confidence_threshold=confidence_threshold,
        enabled_types=enabled_types,
    )
    print(f"  {len(filtered)} true positives to remediate")

    if not filtered:
        print("  All findings filtered. Exiting.")
        return []

    # ── Stages 4-8: Agent remediation pipeline (per vulnerability) ──
    results = []
    for i, vuln in enumerate(filtered, 1):
        print(f"\n{'━' * 70}")
        print(f"  Processing vulnerability {i}/{len(filtered)}")
        print(f"  {vuln['vuln_type']} - {vuln['file_path']}:{vuln['line_number']}")
        print(f"{'━' * 70}")

        try:
            result = run_remediation(
                vulnerability=vuln,
                repo_path=repo_path,
                interactive_mode=interactive,
                max_retries=max_retries,
            )
            results.append(result)

            status = result.get('status', 'UNKNOWN')
            print(f"\n  Result: {status}")
            if result.get('summary'):
                print(f"  {result['summary']}")

        except Exception as e:
            print(f"\n  ❌ Error processing {vuln['vuln_type']}: {e}")
            results.append({
                'vulnerability': vuln,
                'status': 'ERROR',
                'error': str(e),
                'summary': f"Error: {e}",
            })

    # ── Summary report ──
    print(f"\n{'=' * 70}")
    print("  PIPELINE COMPLETE - Generating summary report...")
    print(f"{'=' * 70}")

    summary_path = generate_summary_report(results, repo_path=repo_path)
    print(f"\n  Summary report: {summary_path}")

    # Print final stats
    verified = sum(1 for r in results if r.get('status') == 'VERIFIED')
    unverified = sum(1 for r in results if r.get('status') == 'UNVERIFIED')
    skipped = sum(1 for r in results if r.get('status') == 'SKIPPED')
    errors = sum(1 for r in results if r.get('status') == 'ERROR')
    total = len(results)

    print(f"\n  ✅ Verified:   {verified}/{total}")
    print(f"  ⚠️  Unverified: {unverified}/{total}")
    print(f"  ⏭️  Skipped:    {skipped}/{total}")
    if errors:
        print(f"  ❌ Errors:     {errors}/{total}")
    if total > 0:
        print(f"  📊 Accuracy:   {verified/total*100:.0f}%")

    return results


def main():
    """CLI entry point."""
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="SecureGuard AI - Security Vulnerability Detection & Code Remediation Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --scan report.json --repo ./myproject
  python main.py --scan report.json --repo ./myproject --interactive
  python main.py --scan report.json --repo ./myproject --vuln-types sql_injection,xss
  python main.py --scan report.json --repo ./myproject --config custom_config.yaml
        """,
    )

    parser.add_argument(
        "--scan", required=True,
        help="Path to the SAST scan report (JSON format)",
    )
    parser.add_argument(
        "--repo", required=True,
        help="Path to the target repository",
    )
    parser.add_argument(
        "--interactive", action="store_true",
        help="Enable interactive mode (human-in-the-loop review)",
    )
    parser.add_argument(
        "--config",
        help="Path to custom vuln_config.yaml",
    )
    parser.add_argument(
        "--vuln-types",
        help="Comma-separated list of vulnerability types to scan (default: all configured)",
    )
    parser.add_argument(
        "--max-retries", type=int, default=3,
        help="Maximum fix attempts per vulnerability (default: 3)",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable verbose output",
    )

    args = parser.parse_args()

    # Parse vuln types if provided
    vuln_types = None
    if args.vuln_types:
        vuln_types = [t.strip() for t in args.vuln_types.split(',')]

    # Validate inputs
    if not os.path.exists(args.scan):
        print(f"Error: Scan report not found: {args.scan}")
        sys.exit(1)

    if not os.path.isdir(args.repo):
        print(f"Error: Repository not found: {args.repo}")
        sys.exit(1)

    # Check for API key (provider-aware)
    try:
        llm_cfg = _load_llm_config()
        check_api_key(llm_cfg["provider"])
    except EnvironmentError as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Run pipeline
    results = run_pipeline(
        scan_report=args.scan,
        repo_path=args.repo,
        interactive=args.interactive,
        config_path=args.config,
        vuln_types=vuln_types,
        max_retries=args.max_retries,
        verbose=args.verbose,
    )

    # Exit code based on results
    if not results:
        sys.exit(0)

    has_errors = any(r.get('status') == 'ERROR' for r in results)
    sys.exit(1 if has_errors else 0)


if __name__ == "__main__":
    main()
