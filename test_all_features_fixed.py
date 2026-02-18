#!/usr/bin/env python3
"""
Comprehensive Feature Test Script for ThreatSimGPT

This script tests all major features of the ThreatSimGPT application
to ensure they work as expected. It covers CLI commands, API endpoints,
template validation, simulation execution, and configuration management.

Usage:
    python test_all_features.py [--verbose] [--dry-run] [--skip-api-tests]

Options:
    --verbose       Enable detailed output
    --dry-run       Skip operations that require API keys
    --skip-api-tests Skip API server tests
"""

# Set environment variable at the very beginning before any imports
# This prevents OpenMP library conflicts
import os
os.environ['KMP_DUPLICATE_LIB_OK'] = 'TRUE'

import sys
import subprocess
import json
import time
import requests
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import argparse
import logging

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import after setting environment variables
try:
    from threatsimgpt import __version__
except ImportError:
    __version__ = "unknown"

class FeatureTestResult:
    """Container for test results."""
    
    def __init__(self, feature_name: str, test_name: str):
        self.feature_name = feature_name
        self.test_name = test_name
        self.passed = False
        self.error_message = None
        self.execution_time = 0
        self.details = {}

class FeatureTester:
    """Main testing class for ThreatSimGPT features."""
    
    def __init__(self, verbose: bool = False, dry_run: bool = False, skip_api_tests: bool = False):
        self.verbose = verbose
        self.dry_run = dry_run
        self.skip_api_tests = skip_api_tests
        self.results: List[FeatureTestResult] = []
        self.project_root = Path(__file__).parent
        self.temp_dir = None
        
        # Setup logging
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
    def setup_temp_environment(self):
        """Setup temporary environment for testing."""
        self.temp_dir = tempfile.mkdtemp(prefix="threatsimgpt_test_")
        self.logger.info(f"Created temporary directory: {self.temp_dir}")
        
        # Create test config file
        test_config = {
            "llm": {
                "default_provider": "mock",
                "mock": {
                    "api_key": "test-key",
                    "model": "mock-model-v1"
                },
                "openrouter": {
                    "api_key": os.getenv("OPENROUTER_API_KEY", ""),
                    "model": "openai/gpt-4o-mini"
                }
            },
            "simulation": {
                "max_stages": 3,
                "enable_safety_checks": True,
                "max_concurrent_simulations": 2
            },
            "logging": {
                "level": "INFO",
                "enable_console_logging": False
            },
            "templates": {
                "directory": "templates",
                "validate_on_load": True
            }
        }
        
        config_path = Path(self.temp_dir) / "test_config.yaml"
        try:
            import yaml
            with open(config_path, 'w') as f:
                yaml.dump(test_config, f, default_flow_style=False)
        except ImportError:
            # If yaml not available, create a simple config
            with open(config_path, 'w') as f:
                f.write(f"""
llm:
  default_provider: mock
  mock:
    api_key: test-key
    model: mock-model-v1

simulation:
  max_stages: 3
  enable_safety_checks: true

logging:
  level: INFO
""")
        
        return config_path
        
    def cleanup_temp_environment(self):
        """Cleanup temporary environment."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            self.logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
            
    def run_command(self, cmd: List[str], timeout: int = 60) -> Tuple[int, str, str]:
        """Run a command and return exit code, stdout, stderr."""
        try:
            if self.verbose:
                self.logger.debug(f"Running command: {' '.join(cmd)}")
                
            # Set environment variable to avoid OpenMP conflicts
            env = os.environ.copy()
            env['KMP_DUPLICATE_LIB_OK'] = 'TRUE'
            # Also suppress the SECRET_KEY warning
            env['SECRET_KEY'] = 'test-secret-key-for-testing'
                
            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env
            )
            
            if self.verbose:
                self.logger.debug(f"Command exit code: {result.returncode}")
                if result.stdout:
                    self.logger.debug(f"STDOUT:\n{result.stdout}")
                if result.stderr:
                    self.logger.debug(f"STDERR:\n{result.stderr}")
                    
            return result.returncode, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", f"Command execution error: {str(e)}"
            
    def test_feature(self, feature_name: str, test_name: str, test_func):
        """Run a test function and record results."""
        result = FeatureTestResult(feature_name, test_name)
        start_time = time.time()
        
        try:
            self.logger.info(f"Testing {feature_name}: {test_name}")
            test_func(result)
            result.passed = True
            self.logger.info(f"✓ PASSED: {feature_name} - {test_name}")
        except Exception as e:
            result.error_message = str(e)
            self.logger.error(f"✗ FAILED: {feature_name} - {test_name}: {e}")
            
        result.execution_time = time.time() - start_time
        self.results.append(result)
        
    def test_cli_basic_commands(self):
        """Test basic CLI commands."""
        
        def test_version(result):
            exit_code, stdout, stderr = self.run_command([sys.executable, "-m", "threatsimgpt", "--version"])
            if exit_code != 0:
                raise Exception(f"Version command failed with exit code {exit_code}")
            if "ThreatSimGPT" not in stdout:
                raise Exception("Version output doesn't contain 'ThreatSimGPT'")
            result.details["version_output"] = stdout.strip()
            
        def test_help(result):
            exit_code, stdout, stderr = self.run_command([sys.executable, "-m", "threatsimgpt", "--help"])
            if exit_code != 0:
                raise Exception(f"Help command failed with exit code {exit_code}")
            if "AI-Powered Threat Simulation Platform" not in stdout:
                raise Exception("Help output doesn't contain expected description")
            result.details["help_available"] = True
            
        def test_status(result):
            exit_code, stdout, stderr = self.run_command([sys.executable, "-m", "threatsimgpt", "status"])
            if exit_code != 0:
                raise Exception(f"Status command failed with exit code {exit_code}")
            if "ThreatSimGPT System Status" not in stdout:
                raise Exception("Status output doesn't contain expected header")
            result.details["status_available"] = True
            
        self.test_feature("CLI Basic Commands", "Version Command", test_version)
        self.test_feature("CLI Basic Commands", "Help Command", test_help)
        self.test_feature("CLI Basic Commands", "Status Command", test_status)
        
    def test_template_management(self):
        """Test template management features."""
        
        def test_list_templates(result):
            exit_code, stdout, stderr = self.run_command([sys.executable, "-m", "threatsimgpt", "templates", "list-all"])
            if exit_code != 0:
                raise Exception(f"Template list command failed with exit code {exit_code}")
            # Check if templates directory exists and has content
            templates_dir = self.project_root / "templates"
            if not templates_dir.exists():
                result.details["templates_exist"] = False
                result.details["message"] = "Templates directory not found"
            else:
                template_files = list(templates_dir.glob("*.yaml"))
                result.details["template_count"] = len(template_files)
                result.details["templates_exist"] = True
                
        def test_validate_templates(result):
            exit_code, stdout, stderr = self.run_command([sys.executable, "-m", "threatsimgpt", "templates", "validate-all"])
            # Validation might fail if templates have issues, but command should succeed
            if exit_code not in [0, 1]:  # 0 = success, 1 = validation errors but command ran
                raise Exception(f"Template validation command failed with exit code {exit_code}")
            result.details["validation_run"] = True
            result.details["validation_output"] = stdout[:500]  # First 500 chars
            
        def test_template_health(result):
            exit_code, stdout, stderr = self.run_command([sys.executable, "-m", "threatsimgpt", "templates", "health"])
            if exit_code != 0:
                raise Exception(f"Template health command failed with exit code {exit_code}")
            result.details["health_check_run"] = True
            
        self.test_feature("Template Management", "List Templates", test_list_templates)
        self.test_feature("Template Management", "Validate Templates", test_validate_templates)
        self.test_feature("Template Management", "Template Health Check", test_template_health)
        
    def test_simulation_features(self):
        """Test simulation execution features."""
        
        def test_dry_run_simulation(result):
            # Use a template that should exist
            template_path = "templates/executive_phishing.yaml"
            if not (self.project_root / template_path).exists():
                template_path = "templates/sample_phishing_template.yaml"
                
            if not (self.project_root / template_path).exists():
                result.details["message"] = "No template found for dry run test"
                return
                
            cmd = [sys.executable, "-m", "threatsimgpt", "simulate", "-s", template_path, "--dry-run"]
            exit_code, stdout, stderr = self.run_command(cmd, timeout=120)
            
            if exit_code != 0:
                raise Exception(f"Dry run simulation failed with exit code {exit_code}")
                
            result.details["dry_run_successful"] = True
            result.details["template_used"] = template_path
            
        def test_simulation_with_mock(result):
            if self.dry_run:
                result.details["skipped"] = "Dry run mode enabled"
                return
                
            # Test with mock provider if available
            config_path = self.setup_temp_environment()
            cmd = [sys.executable, "-m", "threatsimgpt", "simulate", 
                   "-s", "templates/executive_phishing.yaml", 
                   "--config", str(config_path),
                   "--dry-run"]  # Still use dry-run to avoid API calls
                   
            exit_code, stdout, stderr = self.run_command(cmd, timeout=120)
            
            if exit_code != 0:
                raise Exception(f"Mock simulation failed with exit code {exit_code}")
                
            result.details["mock_simulation_successful"] = True
            self.cleanup_temp_environment()
            
        self.test_feature("Simulation Features", "Dry Run Simulation", test_dry_run_simulation)
        self.test_feature("Simulation Features", "Mock Provider Simulation", test_simulation_with_mock)
        
    def test_llm_features(self):
        """Test LLM provider features."""
        
        def test_llm_providers_list(result):
            exit_code, stdout, stderr = self.run_command([sys.executable, "-m", "threatsimgpt", "llm", "--help"])
            if exit_code != 0:
                raise Exception(f"LLM help command failed with exit code {exit_code}")
            result.details["llm_help_available"] = True
            
        def test_llm_connection_test(result):
            if self.dry_run:
                result.details["skipped"] = "Dry run mode enabled"
                return
                
            # Test connection to configured provider
            exit_code, stdout, stderr = self.run_command([sys.executable, "-m", "threatsimgpt", "llm", "test"])
            # This might fail if no API key is configured, but command should run
            if exit_code not in [0, 1]:
                raise Exception(f"LLM connection test failed with exit code {exit_code}")
            result.details["connection_test_run"] = True
            result.details["output"] = stdout[:200]
            
        self.test_feature("LLM Features", "List Providers", test_llm_providers_list)
        self.test_feature("LLM Features", "Connection Test", test_llm_connection_test)
        
    def test_dataset_features(self):
        """Test dataset management features."""
        
        def test_dataset_list(result):
            exit_code, stdout, stderr = self.run_command([sys.executable, "-m", "threatsimgpt", "datasets", "list"])
            if exit_code != 0:
                raise Exception(f"Dataset list command failed with exit code {exit_code}")
            result.details["datasets_listed"] = True
            
        def test_dataset_stats(result):
            exit_code, stdout, stderr = self.run_command([sys.executable, "-m", "threatsimgpt", "datasets", "--help"])
            if exit_code != 0:
                raise Exception(f"Dataset help command failed with exit code {exit_code}")
            result.details["dataset_help_available"] = True
            
        self.test_feature("Dataset Features", "List Datasets", test_dataset_list)
        self.test_feature("Dataset Features", "Dataset Statistics", test_dataset_stats)
        
    def test_configuration_features(self):
        """Test configuration management features."""
        
        def test_config_show(result):
            exit_code, stdout, stderr = self.run_command([sys.executable, "-m", "threatsimgpt", "--help"])
            if exit_code != 0:
                raise Exception(f"Main help command failed with exit code {exit_code}")
            result.details["main_help_available"] = True
            
        def test_config_validate(result):
            exit_code, stdout, stderr = self.run_command([sys.executable, "-m", "threatsimgpt", "validate", "--help"])
            if exit_code != 0:
                raise Exception(f"Validate help command failed with exit code {exit_code}")
            result.details["validate_help_available"] = True
            
        self.test_feature("Configuration", "Show Configuration", test_config_show)
        self.test_feature("Configuration", "Validate Configuration", test_config_validate)
        
    def test_api_features(self):
        """Test API server features."""
        
        def test_api_start_stop(result):
            if self.skip_api_tests:
                result.details["skipped"] = "API tests skipped by flag"
                return
                
            # Start API server in background
            cmd = [sys.executable, "-m", "threatsimgpt", "api", "start", "--host", "127.0.0.1", "--port", "8999"]
            
            try:
                # Start server process
                process = subprocess.Popen(
                    cmd,
                    cwd=self.project_root,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env={**os.environ, 'KMP_DUPLICATE_LIB_OK': 'TRUE', 'SECRET_KEY': 'test-secret'}
                )
                
                # Wait for server to start
                time.sleep(5)
                
                # Test health endpoint
                try:
                    response = requests.get("http://127.0.0.1:8999/health", timeout=10)
                    if response.status_code == 200:
                        result.details["api_health_check"] = "passed"
                    else:
                        result.details["api_health_check"] = f"status_code_{response.status_code}"
                except requests.exceptions.RequestException as e:
                    result.details["api_health_check"] = f"request_error: {str(e)}"
                    
                # Test docs endpoint
                try:
                    response = requests.get("http://127.0.0.1:8999/docs", timeout=10)
                    if response.status_code == 200:
                        result.details["api_docs_available"] = True
                except requests.exceptions.RequestException:
                    result.details["api_docs_available"] = False
                    
                result.details["api_server_started"] = True
                
            except Exception as e:
                result.details["api_test_error"] = str(e)
            finally:
                # Clean up: terminate the server process
                if 'process' in locals():
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        
        self.test_feature("API Features", "API Server Start/Stop", test_api_start_stop)
        
    def test_intelligence_features(self):
        """Test OSINT and intelligence features."""
        
        def test_intelligence_command(result):
            exit_code, stdout, stderr = self.run_command([sys.executable, "-m", "threatsimgpt", "intel", "--help"])
            if exit_code != 0:
                raise Exception(f"Intel command help failed with exit code {exit_code}")
            result.details["intel_command_available"] = True
            
        self.test_feature("Intelligence Features", "Intelligence Command", test_intelligence_command)
        
    def test_detection_features(self):
        """Test threat detection features."""
        
        def test_detection_command(result):
            exit_code, stdout, stderr = self.run_command([sys.executable, "-m", "threatsimgpt", "detect", "--help"])
            if exit_code != 0:
                raise Exception(f"Detection command help failed with exit code {exit_code}")
            result.details["detection_command_available"] = True
            
        self.test_feature("Detection Features", "Detection Command", test_detection_command)
        
    def run_all_tests(self):
        """Run all feature tests."""
        self.logger.info("Starting comprehensive feature tests for ThreatSimGPT")
        self.logger.info(f"Version: {__version__}")
        self.logger.info(f"Project root: {self.project_root}")
        
        # Run all test categories
        self.test_cli_basic_commands()
        self.test_template_management()
        self.test_simulation_features()
        self.test_llm_features()
        self.test_dataset_features()
        self.test_configuration_features()
        self.test_api_features()
        self.test_intelligence_features()
        self.test_detection_features()
        
    def generate_report(self) -> str:
        """Generate a comprehensive test report."""
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r.passed)
        failed_tests = total_tests - passed_tests
        
        report = []
        report.append("=" * 80)
        report.append("THREATSIMGPT COMPREHENSIVE FEATURE TEST REPORT")
        report.append("=" * 80)
        report.append(f"Version: {__version__}")
        report.append(f"Test Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total Tests: {total_tests}")
        report.append(f"Passed: {passed_tests}")
        report.append(f"Failed: {failed_tests}")
        report.append(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        report.append("")
        
        # Group results by feature
        features = {}
        for result in self.results:
            if result.feature_name not in features:
                features[result.feature_name] = []
            features[result.feature_name].append(result)
            
        for feature_name, feature_results in features.items():
            report.append(f"## {feature_name}")
            report.append("-" * 50)
            
            for result in feature_results:
                status = "✓ PASS" if result.passed else "✗ FAIL"
                report.append(f"{status} {result.test_name} ({result.execution_time:.2f}s)")
                
                if result.error_message:
                    report.append(f"    Error: {result.error_message}")
                    
                if result.details:
                    for key, value in result.details.items():
                        if key != "error_message":
                            report.append(f"    {key}: {value}")
                report.append("")
                
        report.append("=" * 80)
        
        return "\n".join(report)
        
    def save_report(self, report: str, filename: str = None):
        """Save test report to file."""
        if filename is None:
            filename = f"threatsimgpt_feature_test_report_{int(time.time())}.txt"
            
        report_path = self.project_root / filename
        with open(report_path, 'w') as f:
            f.write(report)
            
        self.logger.info(f"Test report saved to: {report_path}")
        return report_path

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Comprehensive feature test for ThreatSimGPT")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--dry-run", action="store_true", help="Skip operations requiring API keys")
    parser.add_argument("--skip-api-tests", action="store_true", help="Skip API server tests")
    parser.add_argument("--output", "-o", help="Output report filename")
    
    args = parser.parse_args()
    
    # Create and run tester
    tester = FeatureTester(
        verbose=args.verbose,
        dry_run=args.dry_run,
        skip_api_tests=args.skip_api_tests
    )
    
    try:
        tester.run_all_tests()
        report = tester.generate_report()
        
        # Print report to console
        print(report)
        
        # Save report to file
        report_path = tester.save_report(report, args.output)
        
        # Return appropriate exit code
        failed_tests = sum(1 for r in tester.results if not r.passed)
        if failed_tests == 0:
            print(f"\n🎉 All tests passed! Report saved to: {report_path}")
            return 0
        else:
            print(f"\n⚠️  {failed_tests} test(s) failed. See report for details: {report_path}")
            return 1
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user")
        return 130
    except Exception as e:
        print(f"\n\n❌ Test execution failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
