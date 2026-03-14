"""
Performance benchmark comparing original vs refactored validator.

Measures throughput, latency, memory usage, and concurrency performance.
"""

import time
import threading
import psutil
import os
import gc
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List
import statistics

# Import both validators
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'threatsimgpt'))

from threatsimgpt.security.template_validator import TemplateSecurityValidator
from threatsimgpt.security.refactored_validator import RefactoredTemplateSecurityValidator
from threatsimgpt.security.config import SecurityValidatorConfig


class PerformanceBenchmark:
    """Benchmark suite for validator performance comparison."""
    
    def __init__(self):
        """Initialize benchmark."""
        self.test_templates = self._generate_test_templates()
        self.results = {}
    
    def _generate_test_templates(self) -> List[Dict[str, Any]]:
        """Generate test templates with varying complexity."""
        templates = []
        
        # Simple template
        templates.append({
            "name": "simple",
            "description": "Simple test template",
            "steps": [{"action": "test", "target": "simple"}]
        })
        
        # Medium complexity template
        templates.append({
            "name": "medium",
            "description": "Medium complexity template with multiple steps",
            "steps": [
                {"action": "scan", "target": "target1"},
                {"action": "exploit", "target": "target2"},
                {"action": "post_exploit", "target": "target3"}
            ],
            "payloads": ["${jndi:ldap://evil}", "../../../etc/passwd"]
        })
        
        # Complex template
        templates.append({
            "name": "complex",
            "description": "Complex template with many findings",
            "steps": [
                {"action": "recon", "target": f"target{i}"} for i in range(10)
            ],
            "payloads": [
                "${jndi:ldap://evil}",
                "../../../etc/passwd",
                "<script>alert('xss')</script>",
                "password='secret123'",
                "https://192.168.1.1/evil",
                "SELECT * FROM users--",
                "rm -rf /",
                f"{{'a': 1}} * 1000"  # Large payload
            ]
        })
        
        return templates
    
    def measure_memory_usage(self):
        """Get current memory usage in MB."""
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / 1024 / 1024
    
    def benchmark_throughput(self, validator, validator_name: str) -> Dict[str, Any]:
        """Benchmark validation throughput."""
        print(f"\n📊 Benchmarking {validator_name} throughput...")
        
        # Warm up
        for _ in range(10):
            validator.validate_template(self.test_templates[0])
        
        # Measure throughput
        start_time = time.time()
        start_memory = self.measure_memory_usage()
        
        results = []
        for template in self.test_templates * 100:  # 300 validations total
            start = time.time()
            result = validator.validate_template(template)
            end = time.time()
            results.append({
                'duration_ms': (end - start) * 1000,
                'findings_count': len(result.findings),
                'is_secure': result.is_secure
            })
        
        end_time = time.time()
        end_memory = self.measure_memory_usage()
        
        durations = [r['duration_ms'] for r in results]
        
        return {
            'validator': validator_name,
            'total_validations': len(results),
            'total_time_seconds': end_time - start_time,
            'throughput_per_second': len(results) / (end_time - start_time),
            'avg_latency_ms': statistics.mean(durations),
            'p95_latency_ms': statistics.quantiles(durations, n=20)[18],  # 95th percentile
            'p99_latency_ms': statistics.quantiles(durations, n=100)[98],  # 99th percentile
            'min_latency_ms': min(durations),
            'max_latency_ms': max(durations),
            'memory_usage_mb': end_memory - start_memory,
            'avg_findings': statistics.mean([r['findings_count'] for r in results])
        }
    
    def benchmark_concurrency(self, validator, validator_name: str) -> Dict[str, Any]:
        """Benchmark concurrent validation performance."""
        print(f"\n🔄 Benchmarking {validator_name} concurrency...")
        
        def worker(worker_id: int):
            """Worker function for concurrent testing."""
            worker_results = []
            for i in range(20):  # 20 validations per worker
                template = self.test_templates[i % len(self.test_templates)]
                start = time.time()
                try:
                    result = validator.validate_template(template)
                    end = time.time()
                    worker_results.append({
                        'worker_id': worker_id,
                        'duration_ms': (end - start) * 1000,
                        'success': True,
                        'findings_count': len(result.findings)
                    })
                except Exception as e:
                    end = time.time()
                    worker_results.append({
                        'worker_id': worker_id,
                        'duration_ms': (end - start) * 1000,
                        'success': False,
                        'error': str(e)
                    })
            return worker_results
        
        # Run concurrent workers
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker, i) for i in range(10)]
            all_results = []
            for future in as_completed(futures):
                all_results.extend(future.result())
        end_time = time.time()
        
        successful = [r for r in all_results if r['success']]
        failed = [r for r in all_results if not r['success']]
        
        if successful:
            durations = [r['duration_ms'] for r in successful]
            return {
                'validator': validator_name,
                'concurrent_workers': 10,
                'validations_per_worker': 20,
                'total_validations': len(all_results),
                'total_time_seconds': end_time - start_time,
                'successful_validations': len(successful),
                'failed_validations': len(failed),
                'success_rate': len(successful) / len(all_results),
                'concurrent_throughput_per_second': len(successful) / (end_time - start_time),
                'avg_latency_ms': statistics.mean(durations),
                'p95_latency_ms': statistics.quantiles(durations, n=20)[18],
            }
        else:
            return {
                'validator': validator_name,
                'concurrent_workers': 10,
                'total_validations': len(all_results),
                'successful_validations': 0,
                'failed_validations': len(failed),
                'success_rate': 0.0,
                'concurrent_throughput_per_second': 0,
            }
    
    def benchmark_cache_performance(self, validator, validator_name: str) -> Dict[str, Any]:
        """Benchmark cache performance."""
        print(f"\n💾 Benchmarking {validator_name} cache performance...")
        
        template = self.test_templates[0]
        
        # First validation (cache miss)
        start1 = time.time()
        result1 = validator.validate_template(template)
        time1 = (time.time() - start1) * 1000
        
        # Second validation (cache hit)
        start2 = time.time()
        result2 = validator.validate_template(template)
        time2 = (time.time() - start2) * 1000
        
        # Third validation (cache hit)
        start3 = time.time()
        result3 = validator.validate_template(template)
        time3 = (time.time() - start3) * 1000
        
        cache_speedup = time1 / time2 if time2 > 0 else 0
        
        return {
            'validator': validator_name,
            'first_validation_ms': time1,
            'second_validation_ms': time2,
            'third_validation_ms': time3,
            'cache_speedup': cache_speedup,
            'cache_hit_faster': time2 < time1,
            'results_consistent': (
                result1.template_hash == result2.template_hash == result3.template_hash and
                len(result1.findings) == len(result2.findings) == len(result3.findings)
            )
        }
    
    def run_full_benchmark(self) -> Dict[str, Any]:
        """Run complete benchmark suite."""
        print("🚀 Starting Performance Benchmark")
        print("=" * 60)
        
        # Initialize validators
        print("Initializing validators...")
        old_validator = TemplateSecurityValidator()
        new_config = SecurityValidatorConfig(
            enable_caching=True,
            rate_limit_enabled=False  # Disable for fair comparison
        )
        new_validator = RefactoredTemplateSecurityValidator(config=new_config)
        
        results = {}
        
        # Throughput benchmark
        results['old_throughput'] = self.benchmark_throughput(old_validator, "Original")
        results['new_throughput'] = self.benchmark_throughput(new_validator, "Refactored")
        
        # Concurrency benchmark
        results['old_concurrency'] = self.benchmark_concurrency(old_validator, "Original")
        results['new_concurrency'] = self.benchmark_concurrency(new_validator, "Refactored")
        
        # Cache benchmark
        results['old_cache'] = self.benchmark_cache_performance(old_validator, "Original")
        results['new_cache'] = self.benchmark_cache_performance(new_validator, "Refactored")
        
        return results
    
    def print_results(self, results: Dict[str, Any]) -> None:
        """Print benchmark results in a formatted way."""
        print("\n" + "=" * 60)
        print("📈 BENCHMARK RESULTS")
        print("=" * 60)
        
        # Throughput comparison
        print("\n📊 THROUGHPUT COMPARISON")
        print("-" * 40)
        old_t = results['old_throughput']
        new_t = results['new_throughput']
        
        print(f"Original Validator:")
        print(f"  Throughput: {old_t['throughput_per_second']:.2f} validations/sec")
        print(f"  Avg Latency: {old_t['avg_latency_ms']:.2f}ms")
        print(f"  P95 Latency: {old_t['p95_latency_ms']:.2f}ms")
        print(f"  Memory: {old_t['memory_usage_mb']:.1f}MB")
        
        print(f"\nRefactored Validator:")
        print(f"  Throughput: {new_t['throughput_per_second']:.2f} validations/sec")
        print(f"  Avg Latency: {new_t['avg_latency_ms']:.2f}ms")
        print(f"  P95 Latency: {new_t['p95_latency_ms']:.2f}ms")
        print(f"  Memory: {new_t['memory_usage_mb']:.1f}MB")
        
        # Calculate improvements
        throughput_improvement = (new_t['throughput_per_second'] / old_t['throughput_per_second'] - 1) * 100
        latency_improvement = (1 - new_t['avg_latency_ms'] / old_t['avg_latency_ms']) * 100
        memory_improvement = (1 - new_t['memory_usage_mb'] / old_t['memory_usage_mb']) * 100
        
        print(f"\n📈 IMPROVEMENTS")
        print("-" * 40)
        print(f"  Throughput: {throughput_improvement:+.1f}%")
        print(f"  Latency: {latency_improvement:+.1f}%")
        print(f"  Memory: {memory_improvement:+.1f}%")
        
        # Concurrency comparison
        print("\n🔄 CONCURRENCY COMPARISON")
        print("-" * 40)
        old_c = results['old_concurrency']
        new_c = results['new_concurrency']
        
        print(f"Original Success Rate: {old_c['success_rate']*100:.1f}%")
        print(f"Refactored Success Rate: {new_c['success_rate']*100:.1f}%")
        
        concurrency_improvement = (new_c['concurrent_throughput_per_second'] / old_c['concurrent_throughput_per_second'] - 1) * 100
        print(f"Concurrent Throughput: {concurrency_improvement:+.1f}%")
        
        # Cache comparison
        print("\n💾 CACHE COMPARISON")
        print("-" * 40)
        old_cache = results['old_cache']
        new_cache = results['new_cache']
        
        print(f"Original Cache Speedup: {old_cache.get('cache_speedup', 0):.1f}x")
        print(f"Refactored Cache Speedup: {new_cache.get('cache_speedup', 0):.1f}x")
        
        # Summary
        print("\n🎯 SUMMARY")
        print("-" * 40)
        if throughput_improvement > 0:
            print("✅ Refactored validator shows better throughput")
        if latency_improvement > 0:
            print("✅ Refactored validator shows better latency")
        if memory_improvement > 0:
            print("✅ Refactored validator uses less memory")
        if new_c['success_rate'] >= old_c['success_rate']:
            print("✅ Refactored validator maintains or improves success rate")
        
        print("\n" + "=" * 60)


def main():
    """Run benchmark suite."""
    benchmark = PerformanceBenchmark()
    
    try:
        results = benchmark.run_full_benchmark()
        benchmark.print_results(results)
        
        print("\n💡 RECOMMENDATIONS")
        print("-" * 40)
        
        # Analyze results and provide recommendations
        if results['new_throughput']['throughput_per_second'] > results['old_throughput']['throughput_per_second']:
            print("• Deploy refactored validator for better throughput")
        
        if results['new_concurrency']['success_rate'] > results['old_concurrency']['success_rate']:
            print("• Use refactored validator for better concurrent performance")
        
        if results['new_cache'].get('cache_speedup', 0) > results['old_cache'].get('cache_speedup', 0):
            print("• Refactored cache implementation is more efficient")
        
        print("• Consider enabling rate limiting in production")
        print("• Monitor metrics via /metrics endpoint")
        print("• Set up health checks via /health endpoint")
        
        return 0
        
    except Exception as e:
        print(f"❌ Benchmark failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
