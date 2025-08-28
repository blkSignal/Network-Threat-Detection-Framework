#!/usr/bin/env python3
"""
Performance and Load Testing for Goliath Systems

This test suite covers:
- Performance benchmarks
- Load testing
- Memory profiling
- CPU profiling
- I/O performance
- Scalability testing
- Resource usage monitoring
"""

import pytest
import time
import psutil
import gc
import threading
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import statistics
import tempfile
import os
import json
from datetime import datetime, timedelta
import random
import string
import tracemalloc
import cProfile
import pstats
from io import StringIO

# Import our modules
import sys
sys.path.append('../detectors/python')
from dga_detector import DGADetector
from beacon_detector import BeaconDetector
from ml_enhancer import MLThreatDetector
from performance_optimizer import PerformanceOptimizer

# Import API components
sys.path.append('../api')
from server import app
from fastapi.testclient import TestClient


class TestPerformanceBenchmarks:
    """Performance benchmarks for core components."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.dga_detector = DGADetector()
        self.beacon_detector = BeaconDetector()
        self.ml_detector = MLThreatDetector()
        self.optimizer = PerformanceOptimizer()
        
        # Generate test datasets
        self.small_domains = [f"domain{i}.com" for i in range(100)]
        self.medium_domains = [f"domain{i}.com" for i in range(1000)]
        self.large_domains = [f"domain{i}.com" for i in range(10000)]
        
        self.complex_domains = [
            ''.join(random.choices(string.ascii_lowercase + string.digits, k=50))
            for _ in range(1000)
        ]
    
    def test_dga_detector_performance(self):
        """Benchmark DGA detector performance."""
        # Small dataset (100 domains)
        start_time = time.time()
        for domain in self.small_domains:
            self.dga_detector.analyze_domain(domain)
        small_time = time.time() - start_time
        
        # Medium dataset (1000 domains)
        start_time = time.time()
        for domain in self.medium_domains:
            self.dga_detector.analyze_domain(domain)
        medium_time = time.time() - start_time
        
        # Large dataset (10000 domains)
        start_time = time.time()
        for domain in self.large_domains:
            self.dga_detector.analyze_domain(domain)
        large_time = time.time() - start_time
        
        # Performance assertions
        assert small_time < 1.0, f"Small dataset took {small_time:.3f}s, expected <1.0s"
        assert medium_time < 10.0, f"Medium dataset took {medium_time:.3f}s, expected <10.0s"
        assert large_time < 100.0, f"Large dataset took {large_time:.3f}s, expected <100.0s"
        
        # Performance per domain
        small_per_domain = small_time / 100
        medium_per_domain = medium_time / 1000
        large_per_domain = large_time / 10000
        
        print(f"\nDGA Detector Performance:")
        print(f"  Small (100): {small_time:.3f}s ({small_per_domain*1000:.3f}ms per domain)")
        print(f"  Medium (1000): {medium_time:.3f}s ({medium_per_domain*1000:.3f}ms per domain)")
        print(f"  Large (10000): {large_time:.3f}s ({large_per_domain*1000:.3f}ms per domain)")
    
    def test_beacon_detector_performance(self):
        """Benchmark beacon detector performance."""
        # Generate test timestamps
        base_time = datetime.now()
        small_timestamps = [
            base_time + timedelta(seconds=i * 300)
            for i in range(100)
        ]
        medium_timestamps = [
            base_time + timedelta(seconds=i * 300)
            for i in range(1000)
        ]
        
        # Small dataset
        start_time = time.time()
        intervals = self.beacon_detector.calculate_intervals(small_timestamps)
        if intervals:
            self.beacon_detector.calculate_periodicity_score(intervals)
        small_time = time.time() - start_time
        
        # Medium dataset
        start_time = time.time()
        intervals = self.beacon_detector.calculate_intervals(medium_timestamps)
        if intervals:
            self.beacon_detector.calculate_periodicity_score(intervals)
        medium_time = time.time() - start_time
        
        # Performance assertions
        assert small_time < 0.1, f"Small dataset took {small_time:.3f}s, expected <0.1s"
        assert medium_time < 1.0, f"Medium dataset took {medium_time:.3f}s, expected <1.0s"
        
        print(f"\nBeacon Detector Performance:")
        print(f"  Small (100): {small_time:.3f}s")
        print(f"  Medium (1000): {medium_time:.3f}s")
    
    def test_ml_enhancer_performance(self):
        """Benchmark ML enhancer performance."""
        # Generate test data
        small_data = [{'entropy': random.random(), 'length': random.randint(5, 50)} for _ in range(100)]
        medium_data = [{'entropy': random.random(), 'length': random.randint(5, 50)} for _ in range(1000)]
        
        # Train on small dataset
        start_time = time.time()
        self.ml_detector.train_anomaly_detector(small_data)
        small_train_time = time.time() - start_time
        
        # Train on medium dataset
        start_time = time.time()
        self.ml_detector.train_anomaly_detector(medium_data)
        medium_train_time = time.time() - start_time
        
        # Test prediction performance
        start_time = time.time()
        self.ml_detector.detect_anomalies(small_data)
        small_pred_time = time.time() - start_time
        
        start_time = time.time()
        self.ml_detector.detect_anomalies(medium_data)
        medium_pred_time = time.time() - start_time
        
        # Performance assertions
        assert small_train_time < 5.0, f"Small training took {small_train_time:.3f}s, expected <5.0s"
        assert medium_train_time < 30.0, f"Medium training took {medium_train_time:.3f}s, expected <30.0s"
        assert small_pred_time < 1.0, f"Small prediction took {small_pred_time:.3f}s, expected <1.0s"
        assert medium_pred_time < 5.0, f"Medium prediction took {medium_pred_time:.3f}s, expected <5.0s"
        
        print(f"\nML Enhancer Performance:")
        print(f"  Training - Small: {small_train_time:.3f}s, Medium: {medium_train_time:.3f}s")
        print(f"  Prediction - Small: {small_pred_time:.3f}s, Medium: {medium_pred_time:.3f}s")
    
    def test_memory_usage(self):
        """Benchmark memory usage."""
        # Start memory tracking
        tracemalloc.start()
        initial_snapshot = tracemalloc.take_snapshot()
        
        # Process large dataset
        results = []
        for domain in self.large_domains:
            result = self.dga_detector.analyze_domain(domain)
            results.append(result)
        
        # Take final snapshot
        final_snapshot = tracemalloc.take_snapshot()
        tracemalloc.stop()
        
        # Calculate memory difference
        top_stats = final_snapshot.compare_to(initial_snapshot, 'lineno')
        total_memory = sum(stat.size_diff for stat in top_stats if stat.size_diff > 0)
        
        # Memory assertions
        assert total_memory < 100 * 1024 * 1024, f"Memory usage {total_memory/1024/1024:.1f}MB exceeds 100MB limit"
        
        print(f"\nMemory Usage: {total_memory/1024/1024:.1f}MB")
        
        # Force cleanup
        del results
        gc.collect()


class TestLoadTesting:
    """Load testing for the system."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.dga_detector = DGADetector()
        self.client = TestClient(app)
        self.auth_headers = {"Authorization": "Bearer goliath-secure-token"}
    
    def test_concurrent_domain_analysis(self):
        """Test concurrent domain analysis."""
        domains = [f"domain{i}.com" for i in range(1000)]
        
        def analyze_domain(domain):
            return self.dga_detector.analyze_domain(domain)
        
        # Test different concurrency levels
        concurrency_levels = [1, 5, 10, 20, 50]
        results = {}
        
        for workers in concurrency_levels:
            start_time = time.time()
            
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [executor.submit(analyze_domain, domain) for domain in domains]
                results_list = [future.result() for future in futures]
            
            end_time = time.time()
            total_time = end_time - start_time
            throughput = len(domains) / total_time
            
            results[workers] = {
                'time': total_time,
                'throughput': throughput,
                'workers': workers
            }
            
            # Verify all results
            assert len(results_list) == 1000
            assert all(isinstance(r, dict) for r in results_list)
        
        # Print results
        print(f"\nConcurrent Domain Analysis Results:")
        for workers, result in results.items():
            print(f"  {workers:2d} workers: {result['time']:.3f}s, "
                  f"{result['throughput']:.1f} domains/sec")
        
        # Performance assertions
        assert results[10]['throughput'] > results[1]['throughput'], "Concurrency should improve performance"
        assert results[20]['throughput'] > results[1]['throughput'], "Higher concurrency should improve performance"
    
    def test_api_load_testing(self):
        """Test API endpoints under load."""
        # Test health endpoint under load
        def health_request():
            return self.client.get("/health", headers=self.auth_headers)
        
        # Test with increasing load
        load_levels = [10, 50, 100, 200]
        results = {}
        
        for load in load_levels:
            start_time = time.time()
            
            with ThreadPoolExecutor(max_workers=load) as executor:
                futures = [executor.submit(health_request) for _ in range(load)]
                responses = [future.result() for future in futures]
            
            end_time = time.time()
            total_time = end_time - start_time
            success_rate = sum(1 for r in responses if r.status_code == 200) / len(responses)
            avg_response_time = total_time / len(responses)
            
            results[load] = {
                'time': total_time,
                'success_rate': success_rate,
                'avg_response_time': avg_response_time,
                'requests_per_second': load / total_time
            }
            
            # Verify responses
            assert success_rate > 0.95, f"Success rate {success_rate:.2%} below 95% threshold"
        
        # Print results
        print(f"\nAPI Load Testing Results:")
        for load, result in results.items():
            print(f"  {load:3d} requests: {result['success_rate']:.1%} success, "
                  f"{result['avg_response_time']*1000:.1f}ms avg, "
                  f"{result['requests_per_second']:.1f} req/s")
    
    def test_memory_pressure_testing(self):
        """Test system behavior under memory pressure."""
        # Generate very large dataset
        large_domains = [f"domain{i}.com" for i in range(100000)]
        
        # Monitor memory usage
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        # Process in chunks to avoid memory explosion
        chunk_size = 1000
        results = []
        
        for i in range(0, len(large_domains), chunk_size):
            chunk = large_domains[i:i + chunk_size]
            chunk_results = []
            
            for domain in chunk:
                result = self.dga_detector.analyze_domain(domain)
                chunk_results.append(result)
            
            results.extend(chunk_results)
            
            # Check memory usage
            current_memory = process.memory_info().rss
            memory_increase = current_memory - initial_memory
            
            # Memory should not grow excessively
            assert memory_increase < 500 * 1024 * 1024, f"Memory increase {memory_increase/1024/1024:.1f}MB exceeds 500MB limit"
            
            # Force garbage collection periodically
            if i % (chunk_size * 10) == 0:
                gc.collect()
        
        assert len(results) == 100000
        
        # Final cleanup
        del results
        gc.collect()
        
        final_memory = process.memory_info().rss
        memory_cleanup = initial_memory - final_memory
        
        print(f"\nMemory Pressure Test Results:")
        print(f"  Initial memory: {initial_memory/1024/1024:.1f}MB")
        print(f"  Peak memory increase: {(process.memory_info().rss - initial_memory)/1024/1024:.1f}MB")
        print(f"  Memory cleanup: {memory_cleanup/1024/1024:.1f}MB")


class TestScalabilityTesting:
    """Scalability testing for the system."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.dga_detector = DGADetector()
        self.beacon_detector = BeaconDetector()
    
    def test_dataset_scalability(self):
        """Test how the system scales with dataset size."""
        dataset_sizes = [100, 1000, 10000, 50000]
        results = {}
        
        for size in dataset_sizes:
            # Generate dataset
            domains = [f"domain{i}.com" for i in range(size)]
            
            # Measure processing time
            start_time = time.time()
            results_list = []
            
            for domain in domains:
                result = self.dga_detector.analyze_domain(domain)
                results_list.append(result)
            
            end_time = time.time()
            processing_time = end_time - start_time
            
            # Calculate metrics
            throughput = size / processing_time
            memory_per_item = psutil.Process().memory_info().rss / size
            
            results[size] = {
                'size': size,
                'time': processing_time,
                'throughput': throughput,
                'memory_per_item': memory_per_item
            }
            
            # Verify results
            assert len(results_list) == size
            assert all(isinstance(r, dict) for r in results_list)
            
            # Cleanup
            del results_list
            gc.collect()
        
        # Print scalability results
        print(f"\nDataset Scalability Results:")
        for size, result in results.items():
            print(f"  {size:5d} items: {result['time']:.3f}s, "
                  f"{result['throughput']:.1f} items/sec, "
                  f"{result['memory_per_item']/1024:.1f}KB/item")
        
        # Scalability assertions
        for i in range(1, len(dataset_sizes)):
            current_size = dataset_sizes[i]
            prev_size = dataset_sizes[i-1]
            
            # Throughput should not degrade too much with size
            current_throughput = results[current_size]['throughput']
            prev_throughput = results[prev_size]['throughput']
            
            # Allow some degradation but not more than 50%
            assert current_throughput > prev_throughput * 0.5, f"Throughput degraded too much: {current_throughput:.1f} vs {prev_throughput:.1f}"
    
    def test_worker_scalability(self):
        """Test how the system scales with worker count."""
        dataset_size = 1000
        domains = [f"domain{i}.com" for i in range(dataset_size)]
        worker_counts = [1, 2, 4, 8, 16, 32]
        results = {}
        
        def analyze_domain(domain):
            return self.dga_detector.analyze_domain(domain)
        
        for workers in worker_counts:
            start_time = time.time()
            
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [executor.submit(analyze_domain, domain) for domain in domains]
                results_list = [future.result() for future in futures]
            
            end_time = time.time()
            processing_time = end_time - start_time
            throughput = dataset_size / processing_time
            
            results[workers] = {
                'workers': workers,
                'time': processing_time,
                'throughput': throughput,
                'efficiency': throughput / workers  # Throughput per worker
            }
            
            # Verify results
            assert len(results_list) == dataset_size
            assert all(isinstance(r, dict) for r in results_list)
        
        # Print worker scalability results
        print(f"\nWorker Scalability Results:")
        for workers, result in results.items():
            print(f"  {workers:2d} workers: {result['time']:.3f}s, "
                  f"{result['throughput']:.1f} items/sec, "
                  f"{result['efficiency']:.1f} items/sec/worker")
        
        # Scalability assertions
        # Single worker should be baseline
        single_worker_throughput = results[1]['throughput']
        
        # More workers should generally improve performance (up to a point)
        for workers in [2, 4, 8]:
            if workers in results:
                assert results[workers]['throughput'] > single_worker_throughput, f"Adding workers should improve performance"
    
    def test_memory_scalability(self):
        """Test memory usage scaling."""
        dataset_sizes = [1000, 5000, 10000, 20000]
        results = {}
        
        for size in dataset_sizes:
            # Generate dataset
            domains = [f"domain{i}.com" for i in range(size)]
            
            # Measure memory before
            process = psutil.Process()
            initial_memory = process.memory_info().rss
            
            # Process dataset
            results_list = []
            for domain in domains:
                result = self.dga_detector.analyze_domain(domain)
                results_list.append(result)
            
            # Measure memory after
            final_memory = process.memory_info().rss
            memory_used = final_memory - initial_memory
            
            # Calculate memory efficiency
            memory_per_item = memory_used / size
            
            results[size] = {
                'size': size,
                'memory_used': memory_used,
                'memory_per_item': memory_per_item
            }
            
            # Verify results
            assert len(results_list) == size
            assert all(isinstance(r, dict) for r in results_list)
            
            # Cleanup
            del results_list
            gc.collect()
        
        # Print memory scalability results
        print(f"\nMemory Scalability Results:")
        for size, result in results.items():
            print(f"  {size:5d} items: {result['memory_used']/1024/1024:.1f}MB total, "
                  f"{result['memory_per_item']/1024:.1f}KB/item")
        
        # Memory scalability assertions
        # Memory per item should remain relatively constant
        memory_per_item_values = [r['memory_per_item'] for r in results.values()]
        memory_variance = statistics.variance(memory_per_item_values)
        memory_mean = statistics.mean(memory_per_item_values)
        coefficient_of_variation = (memory_variance ** 0.5) / memory_mean
        
        # Memory usage should be relatively consistent per item
        assert coefficient_of_variation < 0.5, f"Memory usage per item varies too much: CV={coefficient_of_variation:.3f}"


class TestResourceMonitoring:
    """Resource usage monitoring during tests."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.dga_detector = DGADetector()
        self.monitoring_data = []
    
    def test_cpu_monitoring(self):
        """Monitor CPU usage during processing."""
        # Start monitoring
        process = psutil.Process()
        
        # Generate dataset
        domains = [f"domain{i}.com" for i in range(10000)]
        
        # Process with CPU monitoring
        start_time = time.time()
        cpu_samples = []
        
        for i, domain in enumerate(domains):
            # Sample CPU every 1000 domains
            if i % 1000 == 0:
                cpu_percent = process.cpu_percent()
                cpu_samples.append(cpu_percent)
            
            self.dga_detector.analyze_domain(domain)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Calculate CPU statistics
        avg_cpu = statistics.mean(cpu_samples) if cpu_samples else 0
        max_cpu = max(cpu_samples) if cpu_samples else 0
        
        print(f"\nCPU Monitoring Results:")
        print(f"  Processing time: {total_time:.3f}s")
        print(f"  Average CPU: {avg_cpu:.1f}%")
        print(f"  Peak CPU: {max_cpu:.1f}%")
        print(f"  Throughput: {len(domains)/total_time:.1f} domains/sec")
        
        # CPU assertions
        assert avg_cpu < 80, f"Average CPU usage {avg_cpu:.1f}% is too high"
        assert max_cpu < 95, f"Peak CPU usage {max_cpu:.1f}% is too high"
    
    def test_memory_monitoring(self):
        """Monitor memory usage during processing."""
        # Start monitoring
        process = psutil.Process()
        
        # Generate dataset
        domains = [f"domain{i}.com" for i in range(20000)]
        
        # Process with memory monitoring
        start_time = time.time()
        memory_samples = []
        
        for i, domain in enumerate(domains):
            # Sample memory every 2000 domains
            if i % 2000 == 0:
                memory_info = process.memory_info()
                memory_samples.append(memory_info.rss)
            
            self.dga_detector.analyze_domain(domain)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Calculate memory statistics
        initial_memory = memory_samples[0] if memory_samples else 0
        peak_memory = max(memory_samples) if memory_samples else 0
        final_memory = memory_samples[-1] if memory_samples else 0
        
        memory_growth = peak_memory - initial_memory
        memory_efficiency = len(domains) / (memory_growth / 1024 / 1024)  # domains per MB
        
        print(f"\nMemory Monitoring Results:")
        print(f"  Processing time: {total_time:.3f}s")
        print(f"  Initial memory: {initial_memory/1024/1024:.1f}MB")
        print(f"  Peak memory: {peak_memory/1024/1024:.1f}MB")
        print(f"  Final memory: {final_memory/1024/1024:.1f}MB")
        print(f"  Memory growth: {memory_growth/1024/1024:.1f}MB")
        print(f"  Memory efficiency: {memory_efficiency:.1f} domains/MB")
        
        # Memory assertions
        assert memory_growth < 500 * 1024 * 1024, f"Memory growth {memory_growth/1024/1024:.1f}MB is too high"
        assert memory_efficiency > 10, f"Memory efficiency {memory_efficiency:.1f} domains/MB is too low"
    
    def test_io_monitoring(self):
        """Monitor I/O operations during processing."""
        # Create temporary files for I/O testing
        temp_files = []
        try:
            # Generate test files
            for i in range(100):
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                    f.write(f"1704067200.000000\tabc{i}\t192.168.1.100\t12345\t8.8.8.8\t53\tudp\t12345\t0.001\ttest{i}.com\t1\tC_INTERNET\t1\tA\t0\tNOERROR\tF\tF\tT\tT\t0\t-\t-\tF\n")
                    temp_files.append(f.name)
            
            # Monitor I/O during file processing
            process = psutil.Process()
            initial_io = process.io_counters()
            
            start_time = time.time()
            all_results = []
            
            for temp_file in temp_files:
                results = self.dga_detector.process_zeek_log(temp_file)
                all_results.extend(results)
            
            end_time = time.time()
            final_io = process.io_counters()
            
            # Calculate I/O statistics
            total_time = end_time - start_time
            read_bytes = final_io.read_bytes - initial_io.read_bytes
            write_bytes = final_io.write_bytes - initial_io.write_bytes
            read_count = final_io.read_count - initial_io.read_count
            write_count = final_io.write_count - initial_io.write_count
            
            print(f"\nI/O Monitoring Results:")
            print(f"  Processing time: {total_time:.3f}s")
            print(f"  Read bytes: {read_bytes/1024:.1f}KB")
            print(f"  Write bytes: {write_bytes/1024:.1f}KB")
            print(f"  Read operations: {read_count}")
            print(f"  Write operations: {write_count}")
            print(f"  I/O throughput: {len(all_results)/total_time:.1f} results/sec")
            
            # I/O assertions
            assert read_count > 0, "Should perform read operations"
            assert len(all_results) == 100, "Should process all files"
            
        finally:
            # Cleanup
            for temp_file in temp_files:
                try:
                    os.unlink(temp_file)
                except:
                    pass


class TestProfiling:
    """Code profiling and performance analysis."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.dga_detector = DGADetector()
    
    def test_dga_detector_profiling(self):
        """Profile DGA detector performance."""
        # Generate test data
        domains = [f"domain{i}.com" for i in range(1000)]
        
        # Create profiler
        profiler = cProfile.Profile()
        profiler.enable()
        
        # Run analysis
        for domain in domains:
            self.dga_detector.analyze_domain(domain)
        
        profiler.disable()
        
        # Get statistics
        stats_stream = StringIO()
        stats = pstats.Stats(profiler, stream=stats_stream)
        stats.sort_stats('cumulative')
        stats.print_stats(20)  # Top 20 functions
        
        # Print profiling results
        print(f"\nDGA Detector Profiling Results:")
        print(stats_stream.getvalue())
        
        # Performance assertions
        # The most time should be spent in core analysis functions
        stats_dict = stats.get_stats_profile()
        total_time = sum(stat.tottime for stat in stats_dict.values())
        
        # Check if core functions are in top performers
        core_functions = ['analyze_domain', 'calculate_entropy', 'calculate_length_score']
        core_time = 0
        
        for func_name, stat in stats_dict.items():
            if any(core_func in func_name for core_func in core_functions):
                core_time += stat.tottime
        
        core_percentage = (core_time / total_time) * 100 if total_time > 0 else 0
        assert core_percentage > 50, f"Core functions should use >50% of time, got {core_percentage:.1f}%"
    
    def test_memory_profiling(self):
        """Profile memory usage patterns."""
        # Start memory tracking
        tracemalloc.start()
        
        # Generate and process large dataset
        domains = [f"domain{i}.com" for i in range(5000)]
        results = []
        
        for domain in domains:
            result = self.dga_detector.analyze_domain(domain)
            results.append(result)
        
        # Take snapshot
        snapshot = tracemalloc.take_snapshot()
        tracemalloc.stop()
        
        # Analyze memory usage
        top_stats = snapshot.statistics('lineno')
        
        print(f"\nMemory Profiling Results:")
        print(f"  Top memory allocations:")
        for stat in top_stats[:10]:
            print(f"    {stat.count:8d} blocks: {stat.size/1024:.1f}KB")
            print(f"      {stat.traceback.format()}")
        
        # Memory assertions
        total_memory = sum(stat.size for stat in top_stats)
        assert total_memory < 100 * 1024 * 1024, f"Total memory usage {total_memory/1024/1024:.1f}MB exceeds 100MB limit"
        
        # Cleanup
        del results
        gc.collect()


if __name__ == '__main__':
    pytest.main([__file__, "-v", "--tb=short"])
