"""Unit tests for CLI functionality."""

import pytest
from click.testing import CliRunner

from threatsimgpt.cli.main import cli


class TestCLI:
    """Test cases for CLI interface."""
    
    def test_cli_version(self):
        """Test CLI version command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "ThreatSimGPT" in result.output
    
    def test_cli_help(self):
        """Test CLI help command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "AI-Powered Threat Simulation Platform" in result.output
    
    def test_simulate_command_help(self):
        """Test simulate command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["simulate", "--help"])
        assert result.exit_code == 0
        assert "Execute a threat simulation scenario" in result.output
    
    def test_templates_command(self):
        """Test templates command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["templates", "list-all"])
        assert result.exit_code == 0
        # Accept either templates found or no templates directory message
        assert "Threat Scenario Templates" in result.output or "No templates directory found" in result.output
    
    def test_status_command(self):
        """Test status command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["status"])
        assert result.exit_code == 0
        assert "ThreatSimGPT System Status" in result.output