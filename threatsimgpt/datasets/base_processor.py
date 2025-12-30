"""Base dataset processor for ThreatSimGPT.

This module provides a foundation for all dataset processors, eliminating duplicate
download logic, parsing patterns, and error handling.
"""

import logging
import aiohttp
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class BaseDatasetProcessor(ABC):
    """Abstract base class for dataset processors.

    This class provides common functionality for downloading, processing, and managing
    datasets. Subclasses should implement abstract methods for dataset-specific logic.
    """

    def __init__(self, storage_path: str):
        """Initialize the dataset processor.

        Args:
            storage_path: Path where datasets will be stored
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

        # HTTP session for connection pooling
        self._session: Optional[aiohttp.ClientSession] = None

        # Tracking
        self._last_download: Optional[datetime] = None
        self._processing_stats: Dict[str, Any] = {}

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session with connection pooling.

        Returns:
            aiohttp.ClientSession instance
        """
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=300),  # 5 minute timeout
                connector=aiohttp.TCPConnector(limit=10)
            )
        return self._session

    async def cleanup(self):
        """Clean up resources (close HTTP session)."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def __aenter__(self):
        """Context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        await self.cleanup()

    async def download_file(
        self,
        url: str,
        destination: Path,
        chunk_size: int = 8192,
        progress_interval: int = 10 * 1024 * 1024  # 10MB
    ) -> bool:
        """Download a file from URL with progress tracking.

        Args:
            url: URL to download from
            destination: Local path to save file
            chunk_size: Size of chunks to download (bytes)
            progress_interval: Interval for progress logging (bytes)

        Returns:
            True if download successful, False otherwise
        """
        try:
            session = await self._get_session()

            logger.info(f"Downloading from {url}")
            async with session.get(url) as response:
                if response.status != 200:
                    logger.error(f"Failed to download: HTTP {response.status}")
                    return False

                total_size = int(response.headers.get('content-length', 0))
                downloaded = 0

                with open(destination, 'wb') as f:
                    async for chunk in response.content.iter_chunked(chunk_size):
                        f.write(chunk)
                        downloaded += len(chunk)

                        # Log progress at intervals
                        if progress_interval > 0 and downloaded % progress_interval < chunk_size:
                            if total_size > 0:
                                progress = (downloaded / total_size) * 100
                                logger.info(f"Download progress: {progress:.1f}% ({downloaded}/{total_size} bytes)")
                            else:
                                logger.info(f"Downloaded: {downloaded} bytes")

                self._last_download = datetime.now()
                logger.info(f"Download completed: {destination}")
                return True

        except aiohttp.ClientError as e:
            logger.error(f"HTTP error downloading {url}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error downloading {url}: {e}")
            return False

    def is_data_recent(self, file_path: Path, max_age_days: int = 7) -> bool:
        """Check if data file is recent enough to skip re-download.

        Args:
            file_path: Path to data file
            max_age_days: Maximum age in days before re-download needed

        Returns:
            True if file exists and is recent, False otherwise
        """
        if not file_path.exists():
            return False

        file_age = datetime.now() - datetime.fromtimestamp(file_path.stat().st_mtime)
        return file_age < timedelta(days=max_age_days)

    def get_file_size_mb(self, file_path: Path) -> float:
        """Get file size in megabytes.

        Args:
            file_path: Path to file

        Returns:
            File size in MB, or 0 if file doesn't exist
        """
        if not file_path.exists():
            return 0.0
        return file_path.stat().st_size / (1024 * 1024)

    @abstractmethod
    async def download_dataset(self) -> bool:
        """Download the dataset.

        Must be implemented by subclasses to define dataset-specific download logic.

        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    async def process_dataset(self) -> bool:
        """Process the downloaded dataset.

        Must be implemented by subclasses to define dataset-specific processing logic.

        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the processed dataset.

        Must be implemented by subclasses to return dataset-specific statistics.

        Returns:
            Dictionary with dataset statistics
        """
        pass

    def get_processing_info(self) -> Dict[str, Any]:
        """Get general processing information.

        Returns:
            Dictionary with processing metadata
        """
        return {
            "storage_path": str(self.storage_path),
            "last_download": self._last_download.isoformat() if self._last_download else None,
            "processing_stats": self._processing_stats
        }
