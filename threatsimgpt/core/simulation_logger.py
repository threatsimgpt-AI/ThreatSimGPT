"""Simulation result logging system for ThreatSimGPT.

This module handles saving simulation results to files with proper validation,
organization, and retrieval capabilities.
"""

import json
import yaml
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
import shutil
import gzip

from .output_models import SimulationOutput, OutputFormat, SimulationOutputValidator

logger = logging.getLogger(__name__)


class SimulationLogger:
    """Handles saving and retrieving simulation results."""

    def __init__(self, logs_directory: str = "logs", auto_create: bool = True):
        """Initialize simulation logger.

        Args:
            logs_directory: Base directory for logs
            auto_create: Whether to automatically create directories
        """
        self.logs_dir = Path(logs_directory)
        self.simulations_dir = self.logs_dir / "simulations"
        self.archives_dir = self.logs_dir / "archives"

        if auto_create:
            self._setup_directories()

    def _setup_directories(self) -> None:
        """Create necessary directories."""
        directories = [
            self.logs_dir,
            self.simulations_dir,
            self.archives_dir,
            self.simulations_dir / "daily",
            self.simulations_dir / "by_type",
            self.simulations_dir / "successful",
            self.simulations_dir / "failed"
        ]

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Created directory: {directory}")

    def save_simulation_result(
        self,
        simulation_output: SimulationOutput,
        format: OutputFormat = OutputFormat.JSON,
        include_metadata: bool = True
    ) -> Path:
        """Save simulation result to file.

        Args:
            simulation_output: Validated simulation output
            format: Output format (JSON, YAML, etc.)
            include_metadata: Whether to include metadata files

        Returns:
            Path to the saved file
        """
        # Validate the output
        if not isinstance(simulation_output, SimulationOutput):
            raise ValueError("simulation_output must be a SimulationOutput instance")

        # Create file paths
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        simulation_id = simulation_output.simulation_id
        filename = f"{timestamp}_{simulation_id}.{format.value}"

        # Determine save location based on status
        if simulation_output.success:
            save_dir = self.simulations_dir / "successful"
        else:
            save_dir = self.simulations_dir / "failed"

        # Also save in daily directory
        daily_dir = self.simulations_dir / "daily" / datetime.utcnow().strftime("%Y-%m-%d")
        daily_dir.mkdir(exist_ok=True)

        # And by threat type
        type_dir = self.simulations_dir / "by_type" / simulation_output.scenario.threat_type
        type_dir.mkdir(exist_ok=True)

        # Save main file
        main_file = save_dir / filename
        self._write_file(simulation_output, main_file, format)

        # Save copies in other directories
        daily_file = daily_dir / filename
        type_file = type_dir / filename

        shutil.copy2(main_file, daily_file)
        shutil.copy2(main_file, type_file)

        # Save metadata if requested
        if include_metadata:
            self._save_metadata(simulation_output, main_file.with_suffix('.meta.json'))

        # Update index
        self._update_index(simulation_output, main_file)

        logger.info(f"Simulation result saved: {main_file}")
        return main_file

    def _write_file(self, simulation_output: SimulationOutput, file_path: Path, format: OutputFormat) -> None:
        """Write simulation output to file in specified format."""
        try:
            if format == OutputFormat.JSON:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(simulation_output.to_json())
            elif format == OutputFormat.YAML:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(simulation_output.to_yaml())
            else:
                raise ValueError(f"Unsupported format: {format}")

        except Exception as e:
            logger.error(f"Failed to write file {file_path}: {e}")
            raise

    def _save_metadata(self, simulation_output: SimulationOutput, metadata_file: Path) -> None:
        """Save simulation metadata separately."""
        metadata = {
            "simulation_id": simulation_output.simulation_id,
            "created_at": simulation_output.created_at.isoformat(),
            "status": simulation_output.status,
            "success": simulation_output.success,
            "scenario_name": simulation_output.scenario.name,
            "threat_type": simulation_output.scenario.threat_type,
            "duration_seconds": simulation_output.metrics.duration_seconds,
            "success_rate": simulation_output.metrics.success_rate,
            "content_count": len(simulation_output.generated_content),
            "file_size_bytes": 0  # Will be updated after file is written
        }

        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, default=str)

    def _update_index(self, simulation_output: SimulationOutput, file_path: Path) -> None:
        """Update the simulation index for quick lookups."""
        index_file = self.logs_dir / "simulation_index.json"

        # Load existing index
        index = {}
        if index_file.exists():
            try:
                with open(index_file, 'r', encoding='utf-8') as f:
                    index = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load index: {e}")
                index = {}

        # Add new entry
        index[simulation_output.simulation_id] = {
            "file_path": str(file_path.relative_to(self.logs_dir)),
            "created_at": simulation_output.created_at.isoformat(),
            "scenario_name": simulation_output.scenario.name,
            "threat_type": simulation_output.scenario.threat_type,
            "status": simulation_output.status,
            "success": simulation_output.success,
            "duration_seconds": simulation_output.metrics.duration_seconds
        }

        # Save updated index
        with open(index_file, 'w', encoding='utf-8') as f:
            json.dump(index, f, indent=2, default=str)

    def load_simulation_result(self, simulation_id: str) -> Optional[SimulationOutput]:
        """Load simulation result by ID.

        Args:
            simulation_id: Simulation ID to load

        Returns:
            SimulationOutput if found, None otherwise
        """
        # Check index first
        index_file = self.logs_dir / "simulation_index.json"
        if not index_file.exists():
            logger.warning("No simulation index found")
            return None

        try:
            with open(index_file, 'r', encoding='utf-8') as f:
                index = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load index: {e}")
            return None

        if simulation_id not in index:
            logger.warning(f"Simulation {simulation_id} not found in index")
            return None

        # Load the file
        file_path = self.logs_dir / index[simulation_id]["file_path"]
        if not file_path.exists():
            logger.error(f"Simulation file not found: {file_path}")
            return None

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Determine format from extension
            if file_path.suffix == '.json':
                return SimulationOutputValidator.validate_json_string(content)
            elif file_path.suffix == '.yaml' or file_path.suffix == '.yml':
                return SimulationOutputValidator.validate_yaml_string(content)
            else:
                logger.error(f"Unsupported file format: {file_path.suffix}")
                return None

        except Exception as e:
            logger.error(f"Failed to load simulation {simulation_id}: {e}")
            return None

    def list_simulations(
        self,
        limit: int = 50,
        threat_type: Optional[str] = None,
        success_only: bool = False,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """List simulations with optional filtering.

        Args:
            limit: Maximum number of results
            threat_type: Filter by threat type
            success_only: Only include successful simulations
            start_date: Filter by start date
            end_date: Filter by end date

        Returns:
            List of simulation summaries
        """
        index_file = self.logs_dir / "simulation_index.json"
        if not index_file.exists():
            return []

        try:
            with open(index_file, 'r', encoding='utf-8') as f:
                index = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load index: {e}")
            return []

        # Apply filters
        results = []
        for sim_id, data in index.items():
            # Filter by success
            if success_only and not data.get("success", False):
                continue

            # Filter by threat type
            if threat_type and data.get("threat_type") != threat_type:
                continue

            # Filter by date range
            if start_date or end_date:
                try:
                    created_at = datetime.fromisoformat(data["created_at"])
                    if start_date and created_at < start_date:
                        continue
                    if end_date and created_at > end_date:
                        continue
                except (ValueError, KeyError):
                    continue

            results.append({
                "simulation_id": sim_id,
                **data
            })

        # Sort by creation date (newest first) and limit
        results.sort(key=lambda x: x["created_at"], reverse=True)
        return results[:limit]

    def archive_old_simulations(self, days_old: int = 30, compress: bool = True) -> int:
        """Archive simulations older than specified days.

        Args:
            days_old: Archive simulations older than this many days
            compress: Whether to compress archived files

        Returns:
            Number of simulations archived
        """
        cutoff_date = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        cutoff_date = cutoff_date.replace(day=cutoff_date.day - days_old)

        archived_count = 0

        # Process each directory
        for directory in [self.simulations_dir / "successful", self.simulations_dir / "failed"]:
            if not directory.exists():
                continue

            for file_path in directory.glob("*.json"):
                try:
                    # Parse timestamp from filename
                    timestamp_str = file_path.stem.split('_')[0]
                    file_date = datetime.strptime(timestamp_str, "%Y%m%d")

                    if file_date < cutoff_date:
                        # Archive the file
                        archive_path = self.archives_dir / file_path.name

                        if compress:
                            # Compress to .gz
                            archive_path = archive_path.with_suffix('.json.gz')
                            with open(file_path, 'rb') as f_in:
                                with gzip.open(archive_path, 'wb') as f_out:
                                    shutil.copyfileobj(f_in, f_out)
                        else:
                            shutil.move(file_path, archive_path)

                        # Remove original
                        if file_path.exists():
                            file_path.unlink()

                        archived_count += 1
                        logger.info(f"Archived simulation: {file_path.name}")

                except (ValueError, IndexError) as e:
                    logger.warning(f"Failed to process file {file_path}: {e}")
                    continue

        logger.info(f"Archived {archived_count} old simulations")
        return archived_count

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about stored simulations.

        Returns:
            Dictionary with statistics
        """
        index_file = self.logs_dir / "simulation_index.json"
        if not index_file.exists():
            return {"total_simulations": 0}

        try:
            with open(index_file, 'r', encoding='utf-8') as f:
                index = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load index: {e}")
            return {"error": str(e)}

        stats = {
            "total_simulations": len(index),
            "successful_simulations": sum(1 for data in index.values() if data.get("success", False)),
            "failed_simulations": sum(1 for data in index.values() if not data.get("success", True)),
            "threat_types": {},
            "average_duration": 0,
            "oldest_simulation": None,
            "newest_simulation": None
        }

        # Calculate detailed stats
        durations = []
        dates = []

        for data in index.values():
            # Threat type counts
            threat_type = data.get("threat_type", "unknown")
            stats["threat_types"][threat_type] = stats["threat_types"].get(threat_type, 0) + 1

            # Duration
            duration = data.get("duration_seconds", 0)
            if duration > 0:
                durations.append(duration)

            # Dates
            try:
                date = datetime.fromisoformat(data["created_at"])
                dates.append(date)
            except (ValueError, KeyError):
                pass

        # Calculate averages and extremes
        if durations:
            stats["average_duration"] = sum(durations) / len(durations)

        if dates:
            stats["oldest_simulation"] = min(dates).isoformat()
            stats["newest_simulation"] = max(dates).isoformat()

        return stats
