#!/usr/bin/env python3
"""
Comprehensive Edge Case Testing for Goliath Systems

This test suite covers:
- Boundary conditions
- Error handling
- Performance under stress
- Malformed input handling
- Resource exhaustion scenarios
- Concurrency issues
- Security edge cases
"""

import pytest
import tempfile
import os
import json
import time
import threading
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from unittest.mock import Mock, patch, MagicMock
import psutil
import gc
from datetime import datetime, timedelta
import random
import string

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


class TestEdgeCaseDGADetector:
    """Test DGA detector with extreme edge cases."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.detector = DGADetector()
    
    def test_empty_and_none_inputs(self):
        """Test handling of empty and None inputs."""
        # Empty string
        result = self.detector.analyze_domain("")
        assert result['score'] == 0.0
        assert result['classification'] == 'clean'
        
        # None input (should handle gracefully)
        with pytest.raises(AttributeError):
            self.detector.analyze_domain(None)
        
        # Whitespace only
        result = self.detector.analyze_domain("   ")
        assert result['score'] == 0.0
    
    def test_extremely_long_domains(self):
        """Test domains with extreme lengths."""
        # Very long domain (1000+ characters)
        long_domain = "a" * 1000 + ".com"
        result = self.detector.analyze_domain(long_domain)
        assert result['score'] == 1.0  # Should be max score
        
        # Extremely long domain (10k+ characters)
        extreme_domain = "b" * 10000 + ".xyz"
        result = self.detector.analyze_domain(extreme_domain)
        assert result['score'] == 1.0
    
    def test_special_characters_and_unicode(self):
        """Test domains with special characters and Unicode."""
        # Special characters
        special_chars = "test!@#$%^&*()_+-=[]{}|;':\",./<>?`~.com"
        result = self.detector.analyze_domain(special_chars)
        # Should handle gracefully without crashing
        
        # Unicode characters
        unicode_domain = "tëst-ñame-中文-한글.com"
        result = self.detector.analyze_domain(unicode_domain)
        # Should handle gracefully
        
        # Emoji (edge case)
        emoji_domain = "test🚀emoji.com"
        result = self.detector.analyze_domain(emoji_domain)
        # Should handle gracefully
    
    def test_entropy_edge_cases(self):
        """Test entropy calculation with edge cases."""
        # Single character
        assert self.detector.calculate_entropy("a") == 0.0
        
        # Two identical characters
        assert self.detector.calculate_entropy("aa") == 0.0
        
        # Maximum entropy (random string)
        random_str = ''.join(random.choices(string.ascii_lowercase, k=100))
        entropy = self.detector.calculate_entropy(random_str)
        assert entropy > 4.0  # Should be close to max entropy
    
    def test_malformed_zeek_logs(self):
        """Test handling of malformed Zeek log files."""
        # Empty file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("")
            temp_file = f.name
        
        try:
            results = self.detector.process_zeek_log(temp_file)
            assert results == []
        finally:
            os.unlink(temp_file)
        
        # File with only comments
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("# This is a comment\n# Another comment\n")
            temp_file = f.name
        
        try:
            results = self.detector.process_zeek_log(temp_file)
            assert results == []
        finally:
            os.unlink(temp_file)
        
        # File with malformed lines
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("malformed line\nanother bad line\n")
            temp_file = f.name
        
        try:
            results = self.detector.process_zeek_log(temp_file)
            # Should handle gracefully and skip bad lines
            assert isinstance(results, list)
        finally:
            os.unlink(temp_file)
    
    def test_concurrent_access(self):
        """Test concurrent access to DGA detector."""
        def analyze_domain(domain):
            return self.detector.analyze_domain(domain)
        
        domains = [f"test{i}.com" for i in range(100)]
        
        # Test with ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(analyze_domain, domains))
        
        assert len(results) == 100
        assert all(isinstance(r, dict) for r in results)
        
        # Test with ThreadPoolExecutor for process-like behavior (avoid pickling issues)
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(analyze_domain, domains[:20]))
        
        assert len(results) == 20
        assert all(isinstance(r, dict) for r in results)


class TestEdgeCaseBeaconDetector:
    """Test beacon detector with extreme edge cases."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.detector = BeaconDetector(min_connections=1)
    
    def test_timestamp_edge_cases(self):
        """Test timestamp parsing with edge cases."""
        # Invalid timestamp formats
        assert self.detector.parse_timestamp("invalid") is None
        assert self.detector.parse_timestamp("") is None
        assert self.detector.parse_timestamp("abc123") is None
        
        # Extreme timestamps
        assert self.detector.parse_timestamp("0") is not None  # Unix epoch start
        assert self.detector.parse_timestamp("9999999999") is not None  # Far future
        
        # Negative timestamp
        assert self.detector.parse_timestamp("-1") is not None
    
    def test_interval_calculation_edge_cases(self):
        """Test interval calculation with edge cases."""
        # Single timestamp
        base_time = datetime.now()
        intervals = self.detector.calculate_intervals([base_time])
        assert intervals == []
        
        # Two identical timestamps
        intervals = self.detector.calculate_intervals([base_time, base_time])
        assert intervals == [0.0]
        
        # Reversed timestamps
        future_time = base_time + timedelta(seconds=100)
        intervals = self.detector.calculate_intervals([future_time, base_time])
        assert intervals == [-100.0]  # Negative interval
    
    def test_periodicity_edge_cases(self):
        """Test periodicity scoring with edge cases."""
        # Single interval
        score = self.detector.calculate_periodicity_score([300.0])
        assert score == 0.0
        
        # Zero intervals
        score = self.detector.calculate_periodicity_score([0.0, 0.0, 0.0])
        assert score == 0.0
        
        # Very large intervals
        score = self.detector.calculate_periodicity_score([1000000.0, 1000000.0])
        assert score == 0.0  # Should be outside valid range
    
    def test_memory_intensive_processing(self):
        """Test memory usage with large datasets."""
        # Generate large dataset
        base_time = datetime.now()
        large_dataset = []
        
        for i in range(10000):
            timestamp = base_time + timedelta(seconds=i * 300)
            large_dataset.append(timestamp)
        
        # Process in chunks to avoid memory issues
        chunk_size = 1000
        results = []
        
        for i in range(0, len(large_dataset), chunk_size):
            chunk = large_dataset[i:i + chunk_size]
            intervals = self.detector.calculate_intervals(chunk)
            if intervals:
                score = self.detector.calculate_periodicity_score(intervals)
                results.append(score)
        
        assert len(results) > 0
        
        # Force garbage collection
        gc.collect()
    
    def test_concurrent_processing(self):
        """Test concurrent processing of beacon detection."""
        def process_flow(flow_id):
            base_time = datetime.now()
            timestamps = [
                base_time + timedelta(seconds=i * 300)
                for i in range(10)
            ]
            return self.detector.detect_beaconing(f"flow_{flow_id}", timestamps)
        
        # Test with multiple threads
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(process_flow, i) for i in range(100)]
            results = [future.result() for future in futures]
        
        assert len(results) == 100
        assert all(isinstance(r, dict) for r in results)


class TestEdgeCaseMLEnhancer:
    """Test ML enhancer with edge cases."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.ml_detector = MLThreatDetector()
    
    def test_empty_and_invalid_data(self):
        """Test ML enhancer with empty and invalid data."""
        # Empty data
        with pytest.raises(ValueError):
            self.ml_detector.extract_features([])
        
        # Data with missing keys
        incomplete_data = [{'entropy': 1.0}]  # Missing other required keys
        features = self.ml_detector.extract_features(incomplete_data)
        assert features.shape[0] == 1
        assert features.shape[1] == 8  # 8 features expected
    
    def test_extreme_feature_values(self):
        """Test with extreme feature values."""
        # Very large values
        extreme_data = [{
            'entropy': 1e6,
            'length': 1e6,
            'digit_ratio': 1e6,
            'consonant_ratio': 1e6,
            'base64_score': 1e6,
            'connection_count': 1e6,
            'periodicity_score': 1e6,
            'variance_score': 1e6
        }]
        
        features = self.ml_detector.extract_features(extreme_data)
        assert features.shape == (1, 8)
        
        # Very small values
        tiny_data = [{
            'entropy': 1e-6,
            'length': 1e-6,
            'digit_ratio': 1e-6,
            'consonant_ratio': 1e-6,
            'base64_score': 1e-6,
            'connection_count': 1e-6,
            'periodicity_score': 1e-6,
            'variance_score': 1e-6
        }]
        
        features = self.ml_detector.extract_features(tiny_data)
        assert features.shape == (1, 8)
    
    def test_insufficient_training_data(self):
        """Test training with insufficient data."""
        # Too few samples
        small_data = [{'entropy': 1.0, 'length': 10}] * 5  # Only 5 samples
        
        with pytest.raises(ValueError):
            self.ml_detector.train_anomaly_detector(small_data)
        
        # Just enough samples
        minimal_data = [{'entropy': 1.0, 'length': 10}] * 10  # Exactly 10 samples
        self.ml_detector.train_anomaly_detector(minimal_data)
        assert self.ml_detector.is_trained
    
    def test_model_persistence_edge_cases(self):
        """Test model saving/loading with edge cases."""
        # Train a model first
        data = [{'entropy': 1.0, 'length': 10}] * 20
        self.ml_detector.train_anomaly_detector(data)
        
        # Test saving to invalid path
        with patch('os.makedirs', side_effect=PermissionError):
            with pytest.raises(PermissionError):
                self.ml_detector.save_models()
        
        # Test loading from non-existent path
        self.ml_detector.is_trained = False
        self.ml_detector.load_models()
        assert not self.ml_detector.is_trained


class TestEdgeCasePerformanceOptimizer:
    """Test performance optimizer with edge cases."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.optimizer = PerformanceOptimizer()
    
    def test_system_metrics_edge_cases(self):
        """Test system metrics with edge cases."""
        # Mock psutil to return extreme values
        with patch('psutil.cpu_percent', return_value=100.0):
            with patch('psutil.virtual_memory') as mock_memory:
                mock_memory.return_value.percent = 100.0
                metrics = self.optimizer.get_system_metrics()
                assert metrics['cpu_percent'] == 100.0
                assert metrics['memory_percent'] == 100.0
        
        # Mock psutil to return zero values
        with patch('psutil.cpu_percent', return_value=0.0):
            with patch('psutil.virtual_memory') as mock_memory:
                mock_memory.return_value.percent = 0.0
                metrics = self.optimizer.get_system_metrics()
                assert metrics['cpu_percent'] == 0.0
                assert metrics['memory_percent'] == 0.0
    
    def test_memory_optimization_edge_cases(self):
        """Test memory optimization with edge cases."""
        # Test with very large memory usage
        with patch('psutil.virtual_memory') as mock_memory:
            mock_memory.return_value.used = 100 * 1024 * 1024 * 1024  # 100GB
            result = self.optimizer.optimize_memory_usage()
            assert 'memory_saved_mb' in result
        
        # Test with zero memory usage
        with patch('psutil.virtual_memory') as mock_memory:
            mock_memory.return_value.used = 0
            result = self.optimizer.optimize_memory_usage()
            assert 'memory_saved_mb' in result
    
    def test_cpu_optimization_edge_cases(self):
        """Test CPU optimization with edge cases."""
        # Test with very high CPU count
        with patch('multiprocessing.cpu_count', return_value=1000):
            workers = self.optimizer.optimize_cpu_utilization()
            assert workers <= 2000  # Should cap at reasonable number
        
        # Test with single CPU
        with patch('multiprocessing.cpu_count', return_value=1):
            workers = self.optimizer.optimize_cpu_utilization()
            assert workers <= 2
    
    def test_batch_processing_edge_cases(self):
        """Test batch processing with edge cases."""
        # Empty data
        result = self.optimizer.batch_process_optimization([])
        assert result == []
        
        # Single item
        result = self.optimizer.batch_process_optimization([42])
        assert result == [84]  # Should double the value
        
        # Very large batch size
        data = list(range(100))
        result = self.optimizer.batch_process_optimization(data, batch_size=1000)
        assert result == [i * 2 for i in range(100)]
        
        # Batch size of 1
        result = self.optimizer.batch_process_optimization(data, batch_size=1)
        assert result == [i * 2 for i in range(100)]


class TestEdgeCaseAPI:
    """Test API endpoints with edge cases."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.client = TestClient(app)
        self.auth_headers = {"Authorization": "Bearer goliath-secure-token"}
    
    def test_authentication_edge_cases(self):
        """Test authentication with edge cases."""
        # Health endpoint doesn't require authentication
        response = self.client.get("/health")
        assert response.status_code == 200
        
        # Test an endpoint that requires authentication
        response = self.client.get("/config")
        assert response.status_code == 403  # No token
        
        # Invalid token
        response = self.client.get("/config", headers={"Authorization": "Bearer invalid"})
        assert response.status_code == 401
        
        # Malformed authorization header
        response = self.client.get("/config", headers={"Authorization": "malformed"})
        assert response.status_code == 403
        
        # Empty token
        response = self.client.get("/config", headers={"Authorization": "Bearer "})
        assert response.status_code == 403  # FastAPI returns 403 for malformed auth
    
    def test_dga_detection_edge_cases(self):
        """Test DGA detection with edge cases."""
        # Empty data
        response = self.client.post(
            "/detect/dga",
            json={"data": "", "type": "dga"},
            headers=self.auth_headers
        )
        assert response.status_code == 200
        
        # Very long data
        long_data = "a" * 10000
        response = self.client.post(
            "/detect/dga",
            json={"data": long_data, "type": "dga"},
            headers=self.auth_headers
        )
        assert response.status_code == 200
        
        # Invalid type
        response = self.client.post(
            "/detect/dga",
            json={"data": "test.com", "type": "invalid"},
            headers=self.auth_headers
        )
        assert response.status_code == 200  # Should still process
        
        # Missing required fields
        response = self.client.post(
            "/detect/dga",
            json={"type": "dga"},
            headers=self.auth_headers
        )
        assert response.status_code == 422  # Validation error
    
    def test_beacon_detection_edge_cases(self):
        """Test beacon detection with edge cases."""
        # Empty data
        response = self.client.post(
            "/detect/beacon",
            json={"data": "", "type": "beacon"},
            headers=self.auth_headers
        )
        assert response.status_code == 200
        
        # Very long data
        long_data = "a" * 10000
        response = self.client.post(
            "/detect/beacon",
            json={"data": long_data, "type": "beacon"},
            headers=self.auth_headers
        )
        assert response.status_code == 200
    
    def test_ml_enhancement_edge_cases(self):
        """Test ML enhancement with edge cases."""
        # Empty data
        response = self.client.post(
            "/ml/enhance",
            json=[],
            headers=self.auth_headers
        )
        assert response.status_code == 500  # Should fail with empty data
        
        # Very large dataset
        large_data = [{"entropy": 1.0, "length": 10}] * 10000
        response = self.client.post(
            "/ml/enhance",
            json=large_data,
            headers=self.auth_headers
        )
        assert response.status_code == 200
        
        # Malformed data
        malformed_data = [{"invalid": "data"}] * 100
        response = self.client.post(
            "/ml/enhance",
            json=malformed_data,
            headers=self.auth_headers
        )
        assert response.status_code == 200  # Should handle gracefully
    
    def test_performance_optimization_edge_cases(self):
        """Test performance optimization with edge cases."""
        response = self.client.post(
            "/performance/optimize",
            headers=self.auth_headers
        )
        assert response.status_code == 200
        
        # Test with high load (concurrent requests)
        def make_request():
            return self.client.post(
                "/performance/optimize",
                headers=self.auth_headers
            )
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(20)]
            responses = [future.result() for future in futures]
        
        assert all(r.status_code == 200 for r in responses)
    
    def test_config_endpoint_edge_cases(self):
        """Test config endpoint with edge cases."""
        # Normal request
        response = self.client.get("/config", headers=self.auth_headers)
        assert response.status_code == 200
        
        # Test with missing config file
        with patch('builtins.open', side_effect=FileNotFoundError):
            response = self.client.get("/config", headers=self.auth_headers)
            assert response.status_code == 500
        
        # Test with invalid YAML
        with patch('builtins.open', side_effect=Exception("YAML parse error")):
            response = self.client.get("/config", headers=self.auth_headers)
            assert response.status_code == 500


class TestStressTesting:
    """Stress testing for the entire system."""
    
    def test_memory_stress(self):
        """Test memory usage under stress."""
        detector = DGADetector()
        
        # Generate large dataset
        large_domains = [f"domain{i}.com" for i in range(10000)]
        
        # Process in memory-intensive way
        results = []
        for domain in large_domains:
            result = detector.analyze_domain(domain)
            results.append(result)
        
        assert len(results) == 10000
        
        # Force garbage collection
        gc.collect()
        
        # Check memory usage
        process = psutil.Process()
        memory_info = process.memory_info()
        assert memory_info.rss < 500 * 1024 * 1024  # Should use less than 500MB
    
    def test_cpu_stress(self):
        """Test CPU usage under stress."""
        detector = DGADetector()
        
        # Generate complex domains
        complex_domains = [
            ''.join(random.choices(string.ascii_lowercase + string.digits, k=50))
            for _ in range(1000)
        ]
        
        start_time = time.time()
        
        # Process all domains
        for domain in complex_domains:
            detector.analyze_domain(domain)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Should process 1000 complex domains in reasonable time
        assert processing_time < 10.0  # Less than 10 seconds
    
    def test_concurrent_stress(self):
        """Test concurrent processing under stress."""
        detector = DGADetector()
        
        def process_domain_batch(batch_id):
            domains = [f"domain{i}_{batch_id}.com" for i in range(100)]
            results = []
            for domain in domains:
                result = detector.analyze_domain(domain)
                results.append(result)
            return len(results)
        
        # Process multiple batches concurrently
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(process_domain_batch, i) for i in range(50)]
            results = [future.result() for future in futures]
        
        assert all(r == 100 for r in results)
        assert len(results) == 50
    
    def test_file_io_stress(self):
        """Test file I/O under stress."""
        detector = DGADetector()
        
        # Create many temporary files
        temp_files = []
        try:
            for i in range(100):
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                    f.write(f"1704067200.000000\tabc{i}\t192.168.1.100\t12345\t8.8.8.8\t53\tudp\t12345\t0.001\ttest{i}.com\t1\tC_INTERNET\t1\tA\t0\tNOERROR\tF\tF\tT\tT\t0\t-\t-\tF\n")
                    temp_files.append(f.name)
            
            # Process all files
            all_results = []
            for temp_file in temp_files:
                results = detector.process_zeek_log(temp_file)
                all_results.extend(results)
            
            assert len(all_results) == 100
            
        finally:
            # Clean up
            for temp_file in temp_files:
                try:
                    os.unlink(temp_file)
                except:
                    pass


class TestSecurityEdgeCases:
    """Test security-related edge cases."""
    
    def test_path_traversal_attempts(self):
        """Test path traversal protection."""
        detector = DGADetector()
        
        # Attempt path traversal
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/passwd",
            "C:\\Windows\\System32\\config\\SAM"
        ]
        
        for path in malicious_paths:
            # Should handle gracefully without exposing system files
            result = detector.analyze_domain(path)
            assert isinstance(result, dict)
    
    def test_sql_injection_attempts(self):
        """Test SQL injection protection."""
        detector = DGADetector()
        
        # Attempt SQL injection
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "' OR 1=1 --",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --"
        ]
        
        for input_str in malicious_inputs:
            result = detector.analyze_domain(input_str)
            assert isinstance(result, dict)
    
    def test_xss_attempts(self):
        """Test XSS protection."""
        detector = DGADetector()
        
        # Attempt XSS
        malicious_inputs = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>"
        ]
        
        for input_str in malicious_inputs:
            result = detector.analyze_domain(input_str)
            assert isinstance(result, dict)
    
    def test_command_injection_attempts(self):
        """Test command injection protection."""
        detector = DGADetector()
        
        # Attempt command injection
        malicious_inputs = [
            "; rm -rf /",
            "| cat /etc/passwd",
            "&& shutdown -h now",
            "`whoami`"
        ]
        
        for input_str in malicious_inputs:
            result = detector.analyze_domain(input_str)
            assert isinstance(result, dict)


if __name__ == '__main__':
    pytest.main([__file__, "-v", "--tb=short"])
