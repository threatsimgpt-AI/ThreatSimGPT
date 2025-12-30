"""
Test Utilities & Helpers
========================

Common utilities, assertions, and helpers for enterprise testing.
"""

import asyncio
import functools
import time
from contextlib import contextmanager, asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import (
    Any, Callable, Dict, Generator, List, Optional, 
    Type, TypeVar, Union, AsyncGenerator
)
from unittest.mock import Mock, AsyncMock, MagicMock, patch
import json
import yaml
import tempfile
import shutil
import os
import sys
import logging

T = TypeVar("T")
ExceptionType = TypeVar("ExceptionType", bound=Exception)


# ==========================================
# Performance Utilities
# ==========================================

@dataclass
class PerformanceResult:
    """Result of a performance measurement."""
    elapsed_time: float
    memory_delta: Optional[float] = None
    cpu_percent: Optional[float] = None
    iterations: int = 1
    
    @property
    def avg_time(self) -> float:
        return self.elapsed_time / self.iterations
    
    def __repr__(self) -> str:
        return f"PerformanceResult(elapsed={self.elapsed_time:.4f}s, avg={self.avg_time:.4f}s)"


class Timer:
    """Context manager for timing code execution."""
    
    def __init__(self, name: str = "operation"):
        self.name = name
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.elapsed: float = 0
    
    def __enter__(self) -> "Timer":
        self.start_time = time.perf_counter()
        return self
    
    def __exit__(self, *args):
        self.end_time = time.perf_counter()
        self.elapsed = self.end_time - self.start_time


@contextmanager
def measure_time() -> Generator[Timer, None, None]:
    """Context manager to measure execution time."""
    timer = Timer()
    with timer:
        yield timer


def benchmark(iterations: int = 100):
    """Decorator to benchmark function performance."""
    def decorator(func: Callable[..., T]) -> Callable[..., PerformanceResult]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> PerformanceResult:
            start = time.perf_counter()
            for _ in range(iterations):
                result = func(*args, **kwargs)
            elapsed = time.perf_counter() - start
            return PerformanceResult(
                elapsed_time=elapsed,
                iterations=iterations
            )
        return wrapper
    return decorator


def async_benchmark(iterations: int = 100):
    """Decorator to benchmark async function performance."""
    def decorator(func: Callable[..., T]) -> Callable[..., PerformanceResult]:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> PerformanceResult:
            start = time.perf_counter()
            for _ in range(iterations):
                result = await func(*args, **kwargs)
            elapsed = time.perf_counter() - start
            return PerformanceResult(
                elapsed_time=elapsed,
                iterations=iterations
            )
        return wrapper
    return decorator


# ==========================================
# Custom Assertions
# ==========================================

class AssertionHelpers:
    """Custom assertion helpers for common test patterns."""
    
    @staticmethod
    def assert_dict_contains(actual: Dict, expected: Dict, msg: str = ""):
        """Assert that actual dict contains all key-value pairs from expected."""
        for key, value in expected.items():
            assert key in actual, f"{msg}: Missing key '{key}' in {actual}"
            if isinstance(value, dict) and isinstance(actual[key], dict):
                AssertionHelpers.assert_dict_contains(actual[key], value, f"{msg}.{key}")
            else:
                assert actual[key] == value, f"{msg}: {key}={actual[key]}, expected {value}"
    
    @staticmethod
    def assert_valid_uuid(value: str, msg: str = ""):
        """Assert that value is a valid UUID string."""
        import re
        uuid_pattern = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            re.IGNORECASE
        )
        assert uuid_pattern.match(value), f"{msg}: '{value}' is not a valid UUID"
    
    @staticmethod
    def assert_valid_email(value: str, msg: str = ""):
        """Assert that value is a valid email format."""
        import re
        email_pattern = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')
        assert email_pattern.match(value), f"{msg}: '{value}' is not a valid email"
    
    @staticmethod
    def assert_in_range(value: float, min_val: float, max_val: float, msg: str = ""):
        """Assert that value is within range."""
        assert min_val <= value <= max_val, \
            f"{msg}: {value} not in range [{min_val}, {max_val}]"
    
    @staticmethod
    def assert_response_time(elapsed: float, max_ms: float, msg: str = ""):
        """Assert that response time is within acceptable limit."""
        elapsed_ms = elapsed * 1000
        assert elapsed_ms <= max_ms, \
            f"{msg}: Response time {elapsed_ms:.2f}ms exceeds {max_ms}ms limit"
    
    @staticmethod
    def assert_json_schema(data: Dict, schema: Dict, msg: str = ""):
        """Simple JSON schema validation (required fields and types)."""
        for field, expected_type in schema.items():
            assert field in data, f"{msg}: Missing required field '{field}'"
            if expected_type is not None:
                assert isinstance(data[field], expected_type), \
                    f"{msg}: Field '{field}' expected {expected_type}, got {type(data[field])}"
    
    @staticmethod
    def assert_no_sensitive_data(content: str, sensitive_patterns: List[str] = None):
        """Assert that content doesn't contain sensitive data patterns."""
        import re
        default_patterns = [
            r'password\s*[:=]\s*\S+',
            r'api[_-]?key\s*[:=]\s*\S+',
            r'secret\s*[:=]\s*\S+',
            r'bearer\s+\S{20,}',
            r'sk-[a-zA-Z0-9]{40,}',
        ]
        patterns = sensitive_patterns or default_patterns
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            assert match is None, f"Sensitive data found: {match.group()}"


# ==========================================
# Mock Factories
# ==========================================

class MockFactory:
    """Factory for creating configured mocks."""
    
    @staticmethod
    def llm_provider(
        response_content: str = "Mock LLM response",
        is_available: bool = True,
        fail_on_call: Optional[int] = None
    ) -> Mock:
        """Create a mock LLM provider."""
        mock = AsyncMock()
        mock.is_available.return_value = is_available
        mock.generate_content.return_value = Mock(
            content=response_content,
            provider="mock",
            model="mock-model",
            tokens_used=100
        )
        
        if fail_on_call is not None:
            call_count = [0]
            original_generate = mock.generate_content
            
            async def failing_generate(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] == fail_on_call:
                    raise RuntimeError("Mock provider failure")
                return await original_generate(*args, **kwargs)
            
            mock.generate_content = failing_generate
        
        return mock
    
    @staticmethod
    def http_response(
        status_code: int = 200,
        json_data: Optional[Dict] = None,
        text: str = "",
        headers: Optional[Dict] = None
    ) -> Mock:
        """Create a mock HTTP response."""
        mock = Mock()
        mock.status_code = status_code
        mock.json.return_value = json_data or {}
        mock.text = text
        mock.headers = headers or {}
        mock.ok = 200 <= status_code < 300
        mock.raise_for_status = Mock()
        if not mock.ok:
            mock.raise_for_status.side_effect = Exception(f"HTTP {status_code}")
        return mock
    
    @staticmethod
    def async_http_response(
        status: int = 200,
        json_data: Optional[Dict] = None
    ) -> AsyncMock:
        """Create a mock async HTTP response."""
        mock = AsyncMock()
        mock.status = status
        mock.json = AsyncMock(return_value=json_data or {})
        mock.text = AsyncMock(return_value="")
        return mock
    
    @staticmethod
    def database_session() -> Mock:
        """Create a mock database session."""
        mock = MagicMock()
        mock.execute = AsyncMock()
        mock.commit = AsyncMock()
        mock.rollback = AsyncMock()
        mock.close = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock()
        return mock
    
    @staticmethod
    def file_system(files: Dict[str, str] = None) -> Mock:
        """Create a mock file system."""
        files = files or {}
        mock = Mock()
        
        def mock_read(path):
            path_str = str(path)
            if path_str in files:
                return files[path_str]
            raise FileNotFoundError(path_str)
        
        def mock_exists(path):
            return str(path) in files
        
        mock.read_text = mock_read
        mock.exists = mock_exists
        mock.files = files
        return mock


# ==========================================
# Temporary File/Directory Utilities
# ==========================================

@contextmanager
def temp_directory() -> Generator[Path, None, None]:
    """Create a temporary directory that's cleaned up after use."""
    tmp_dir = Path(tempfile.mkdtemp(prefix="threatsimgpt_test_"))
    try:
        yield tmp_dir
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@contextmanager
def temp_file(
    content: str = "",
    suffix: str = ".txt",
    encoding: str = "utf-8"
) -> Generator[Path, None, None]:
    """Create a temporary file with content."""
    fd, path = tempfile.mkstemp(suffix=suffix, prefix="threatsimgpt_test_")
    try:
        with os.fdopen(fd, 'w', encoding=encoding) as f:
            f.write(content)
        yield Path(path)
    finally:
        os.unlink(path)


@contextmanager
def temp_yaml_file(data: Dict[str, Any]) -> Generator[Path, None, None]:
    """Create a temporary YAML file."""
    content = yaml.dump(data)
    with temp_file(content, suffix=".yaml") as path:
        yield path


@contextmanager
def temp_json_file(data: Dict[str, Any]) -> Generator[Path, None, None]:
    """Create a temporary JSON file."""
    content = json.dumps(data, indent=2)
    with temp_file(content, suffix=".json") as path:
        yield path


# ==========================================
# Environment & Config Utilities
# ==========================================

@contextmanager
def env_vars(**vars) -> Generator[None, None, None]:
    """Temporarily set environment variables."""
    original = {}
    for key, value in vars.items():
        original[key] = os.environ.get(key)
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = str(value)
    try:
        yield
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@contextmanager
def capture_logs(
    logger_name: str = "",
    level: int = logging.DEBUG
) -> Generator[List[logging.LogRecord], None, None]:
    """Capture log records during test."""
    records = []
    
    class ListHandler(logging.Handler):
        def emit(self, record):
            records.append(record)
    
    logger = logging.getLogger(logger_name)
    handler = ListHandler()
    handler.setLevel(level)
    original_level = logger.level
    logger.setLevel(level)
    logger.addHandler(handler)
    
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(original_level)


# ==========================================
# Async Test Utilities
# ==========================================

def run_async(coro):
    """Run async coroutine in sync context."""
    return asyncio.get_event_loop().run_until_complete(coro)


@asynccontextmanager
async def async_timeout(seconds: float):
    """Async context manager with timeout."""
    try:
        async with asyncio.timeout(seconds):
            yield
    except asyncio.TimeoutError:
        raise AssertionError(f"Operation timed out after {seconds}s")


def async_test(timeout: float = 30.0):
    """Decorator for async tests with timeout."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            async def run():
                async with async_timeout(timeout):
                    return await func(*args, **kwargs)
            return asyncio.get_event_loop().run_until_complete(run())
        return wrapper
    return decorator


# ==========================================
# Exception Testing
# ==========================================

@contextmanager
def assert_raises_with_message(
    exception_type: Type[Exception],
    message_contains: str
) -> Generator[None, None, None]:
    """Assert exception is raised with specific message."""
    try:
        yield
        raise AssertionError(f"Expected {exception_type.__name__} was not raised")
    except exception_type as e:
        assert message_contains in str(e), \
            f"Expected message containing '{message_contains}', got '{str(e)}'"


@contextmanager  
def assert_not_raises() -> Generator[None, None, None]:
    """Assert that no exception is raised."""
    try:
        yield
    except Exception as e:
        raise AssertionError(f"Unexpected exception raised: {type(e).__name__}: {e}")


# ==========================================
# Data Comparison Utilities
# ==========================================

def deep_diff(dict1: Dict, dict2: Dict, path: str = "") -> List[str]:
    """Find differences between two dictionaries."""
    differences = []
    
    all_keys = set(dict1.keys()) | set(dict2.keys())
    
    for key in all_keys:
        current_path = f"{path}.{key}" if path else key
        
        if key not in dict1:
            differences.append(f"Missing in first: {current_path}")
        elif key not in dict2:
            differences.append(f"Missing in second: {current_path}")
        elif isinstance(dict1[key], dict) and isinstance(dict2[key], dict):
            differences.extend(deep_diff(dict1[key], dict2[key], current_path))
        elif dict1[key] != dict2[key]:
            differences.append(f"Different at {current_path}: {dict1[key]} != {dict2[key]}")
    
    return differences


def normalize_json(data: Any) -> Any:
    """Normalize JSON data for comparison (sort keys, etc.)."""
    if isinstance(data, dict):
        return {k: normalize_json(v) for k, v in sorted(data.items())}
    elif isinstance(data, list):
        return [normalize_json(item) for item in data]
    return data


# Shorthand assertions
assertions = AssertionHelpers()
