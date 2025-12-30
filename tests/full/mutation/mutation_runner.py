"""
Enterprise Mutation Testing Configuration
=========================================

Configuration and utilities for mutation testing with mutmut.
Validates test quality by measuring ability to detect code changes.
"""

import subprocess
import json
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import Enum


class MutationOperator(Enum):
    """Types of mutations applied to code."""
    ARITHMETIC = "arithmetic"      # +, -, *, /, %
    COMPARISON = "comparison"      # ==, !=, <, >, <=, >=
    LOGICAL = "logical"           # and, or, not
    ASSIGNMENT = "assignment"      # =, +=, -=
    STATEMENT = "statement"        # delete statements
    CONSTANT = "constant"          # change literals
    EXCEPTION = "exception"        # modify exception handling
    DECORATOR = "decorator"        # remove/modify decorators
    RETURN = "return"             # modify return values


@dataclass
class MutationResult:
    """Result of a single mutation."""
    mutation_id: str
    file_path: str
    line_number: int
    operator: MutationOperator
    status: str  # killed, survived, timeout, error
    original_code: str
    mutated_code: str
    test_output: Optional[str] = None


@dataclass
class MutationReport:
    """Complete mutation testing report."""
    total_mutations: int = 0
    killed: int = 0
    survived: int = 0
    timeout: int = 0
    error: int = 0
    
    results: List[MutationResult] = field(default_factory=list)
    
    @property
    def kill_rate(self) -> float:
        """Calculate mutation kill rate (higher is better)."""
        if self.total_mutations == 0:
            return 0.0
        return self.killed / self.total_mutations * 100
    
    @property
    def survival_rate(self) -> float:
        """Calculate mutation survival rate (lower is better)."""
        if self.total_mutations == 0:
            return 0.0
        return self.survived / self.total_mutations * 100
    
    def is_passing(self, min_kill_rate: float = 70.0) -> bool:
        """Check if kill rate meets minimum threshold."""
        return self.kill_rate >= min_kill_rate
    
    def get_survivors_by_file(self) -> Dict[str, List[MutationResult]]:
        """Group surviving mutations by file."""
        survivors = {}
        for result in self.results:
            if result.status == "survived":
                if result.file_path not in survivors:
                    survivors[result.file_path] = []
                survivors[result.file_path].append(result)
        return survivors
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "total_mutations": self.total_mutations,
            "killed": self.killed,
            "survived": self.survived,
            "timeout": self.timeout,
            "error": self.error,
            "kill_rate": round(self.kill_rate, 2),
            "survival_rate": round(self.survival_rate, 2),
            "passing": self.is_passing()
        }


class MutationTestRunner:
    """Runner for mutation testing using mutmut."""
    
    def __init__(
        self,
        source_dir: Path,
        test_dir: Path,
        config_path: Optional[Path] = None
    ):
        self.source_dir = source_dir
        self.test_dir = test_dir
        self.config_path = config_path
        self._report: Optional[MutationReport] = None
    
    def generate_mutmut_config(self) -> str:
        """Generate mutmut configuration."""
        return f'''
[mutmut]
paths_to_mutate = {self.source_dir}
tests_dir = {self.test_dir}
runner = python -m pytest -x --tb=no -q

# Patterns to exclude from mutation
dict_synonyms = Struct, NamedTuple
'''
    
    def run(
        self,
        target_files: Optional[List[str]] = None,
        parallel: int = 1,
        timeout: float = 30.0
    ) -> MutationReport:
        """Run mutation testing."""
        cmd = [
            sys.executable, "-m", "mutmut", "run",
            "--paths-to-mutate", str(self.source_dir),
            "--tests-dir", str(self.test_dir),
            "--runner", f"{sys.executable} -m pytest -x --tb=no -q",
        ]
        
        if parallel > 1:
            cmd.extend(["--parallel", str(parallel)])
        
        if target_files:
            for f in target_files:
                cmd.extend(["--paths-to-mutate", f])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout * 60  # Convert to seconds
            )
            return self._parse_results()
        except subprocess.TimeoutExpired:
            return MutationReport(error=1)
        except FileNotFoundError:
            print("mutmut not installed. Install with: pip install mutmut")
            return MutationReport()
    
    def _parse_results(self) -> MutationReport:
        """Parse mutmut results."""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "mutmut", "results"],
                capture_output=True,
                text=True
            )
            
            report = MutationReport()
            
            # Parse output
            for line in result.stdout.split("\n"):
                if "Killed:" in line:
                    report.killed = int(line.split(":")[1].strip())
                elif "Survived:" in line:
                    report.survived = int(line.split(":")[1].strip())
                elif "Timeout:" in line:
                    report.timeout = int(line.split(":")[1].strip())
            
            report.total_mutations = report.killed + report.survived + report.timeout
            self._report = report
            return report
            
        except Exception as e:
            print(f"Error parsing results: {e}")
            return MutationReport()
    
    def show_survivors(self) -> str:
        """Show surviving mutations."""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "mutmut", "show", "all"],
                capture_output=True,
                text=True
            )
            return result.stdout
        except Exception:
            return ""
    
    def get_report(self) -> Optional[MutationReport]:
        """Get the last mutation report."""
        return self._report


# ==========================================
# Mutation Testing Targets
# ==========================================

# Define which modules to target for mutation testing
MUTATION_TARGETS = {
    "core": {
        "path": "src/threatsimgpt/core",
        "min_kill_rate": 80.0,
        "priority": "high",
        "files": [
            "simulator.py",
            "models.py",
            "output_models.py",
        ]
    },
    "config": {
        "path": "src/threatsimgpt/config",
        "min_kill_rate": 85.0,
        "priority": "high",
        "files": [
            "loader.py",
            "validator.py",
            "models.py",
        ]
    },
    "llm": {
        "path": "src/threatsimgpt/llm",
        "min_kill_rate": 70.0,
        "priority": "medium",
        "files": [
            "base.py",
            "manager.py",
            "generation.py",
        ]
    },
    "safety": {
        "path": "src/threatsimgpt/safety",
        "min_kill_rate": 90.0,
        "priority": "critical",
        "files": [
            "models.py",
        ]
    },
    "intelligence": {
        "path": "src/threatsimgpt/intelligence",
        "min_kill_rate": 75.0,
        "priority": "medium",
        "files": [
            "models.py",
            "services.py",
        ]
    },
}


def run_mutation_tests(
    modules: Optional[List[str]] = None,
    min_kill_rate: float = 70.0
) -> Tuple[bool, Dict[str, MutationReport]]:
    """
    Run mutation tests for specified modules.
    
    Args:
        modules: List of module names to test (None = all)
        min_kill_rate: Minimum required kill rate
    
    Returns:
        Tuple of (all_passed, reports_by_module)
    """
    project_root = Path(__file__).parent.parent.parent
    reports = {}
    all_passed = True
    
    targets = modules or list(MUTATION_TARGETS.keys())
    
    for module in targets:
        if module not in MUTATION_TARGETS:
            print(f"Unknown module: {module}")
            continue
        
        config = MUTATION_TARGETS[module]
        source_path = project_root / config["path"]
        test_path = project_root / "tests"
        
        print(f"\nRunning mutation tests for: {module}")
        print(f"  Source: {source_path}")
        print(f"  Min kill rate: {config['min_kill_rate']}%")
        
        runner = MutationTestRunner(source_path, test_path)
        report = runner.run()
        
        reports[module] = report
        
        if not report.is_passing(config["min_kill_rate"]):
            all_passed = False
            print(f"  ❌ FAILED - Kill rate: {report.kill_rate:.1f}%")
        else:
            print(f"  ✓ PASSED - Kill rate: {report.kill_rate:.1f}%")
    
    return all_passed, reports


def generate_mutation_report(reports: Dict[str, MutationReport]) -> str:
    """Generate a mutation testing summary report."""
    lines = [
        "=" * 60,
        "MUTATION TESTING REPORT",
        "=" * 60,
        ""
    ]
    
    total_mutations = sum(r.total_mutations for r in reports.values())
    total_killed = sum(r.killed for r in reports.values())
    total_survived = sum(r.survived for r in reports.values())
    
    overall_kill_rate = (total_killed / total_mutations * 100) if total_mutations > 0 else 0
    
    lines.extend([
        "SUMMARY",
        "-" * 40,
        f"Total Mutations:  {total_mutations}",
        f"Killed:           {total_killed}",
        f"Survived:         {total_survived}",
        f"Overall Kill Rate: {overall_kill_rate:.1f}%",
        ""
    ])
    
    lines.extend([
        "MODULE BREAKDOWN",
        "-" * 40,
    ])
    
    for module, report in reports.items():
        status = "✓" if report.is_passing() else "❌"
        lines.append(
            f"  {status} {module:20} Kill Rate: {report.kill_rate:5.1f}% "
            f"({report.killed}/{report.total_mutations})"
        )
    
    lines.extend([
        "",
        "=" * 60,
    ])
    
    return "\n".join(lines)


# ==========================================
# CLI for Mutation Testing
# ==========================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Run mutation tests")
    parser.add_argument(
        "--modules", "-m",
        nargs="+",
        help="Modules to test (default: all)"
    )
    parser.add_argument(
        "--min-kill-rate", "-k",
        type=float,
        default=70.0,
        help="Minimum kill rate (default: 70.0)"
    )
    parser.add_argument(
        "--report", "-r",
        action="store_true",
        help="Generate detailed report"
    )
    
    args = parser.parse_args()
    
    passed, reports = run_mutation_tests(
        modules=args.modules,
        min_kill_rate=args.min_kill_rate
    )
    
    if args.report:
        print(generate_mutation_report(reports))
    
    sys.exit(0 if passed else 1)
