#!/usr/bin/env python3
"""
Performance Optimizer for Goliath Systems

Optimizes threat detection pipeline performance through:
- Memory management
- CPU utilization
- I/O optimization
- Cache management
"""

import psutil
import time
import logging
import gc
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import multiprocessing

class PerformanceOptimizer:
    """Optimizes system performance for threat detection."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.optimization_history = []
    
    def get_system_metrics(self) -> Dict:
        """Get current system performance metrics."""
        return {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'network_io': psutil.net_io_counters(),
            'process_count': len(psutil.pids())
        }
    
    def optimize_memory_usage(self) -> Dict:
        """Optimize memory usage for large log processing."""
        gc.collect()  # Force garbage collection
        memory_before = psutil.virtual_memory().used
        
        # Clear any unnecessary caches
        if hasattr(self, '_cache'):
            self._cache.clear()
        
        memory_after = psutil.virtual_memory().used
        saved = memory_before - memory_after
        
        return {
            'memory_saved_mb': saved / (1024 * 1024),
            'optimization_type': 'memory_cleanup'
        }
    
    def optimize_cpu_utilization(self, max_workers: int = None) -> int:
        """Optimize CPU utilization for parallel processing."""
        if max_workers is None:
            max_workers = multiprocessing.cpu_count()
        
        # Ensure we don't overload the system
        optimal_workers = min(max_workers, psutil.cpu_count() * 2)
        
        return optimal_workers
    
    def batch_process_optimization(self, data: List, batch_size: int = 1000) -> List:
        """Process data in optimized batches."""
        results = []
        
        for i in range(0, len(data), batch_size):
            batch = data[i:i + batch_size]
            # Process batch
            batch_results = self._process_batch(batch)
            results.extend(batch_results)
            
            # Yield control to prevent blocking
            time.sleep(0.001)
        
        return results
    
    def _process_batch(self, batch: List) -> List:
        """Process a single batch of data."""
        # Placeholder for batch processing logic
        return [item * 2 for item in batch]  # Example transformation
    
    def get_optimization_recommendations(self) -> List[str]:
        """Get recommendations for performance optimization."""
        metrics = self.get_system_metrics()
        recommendations = []
        
        if metrics['cpu_percent'] > 80:
            recommendations.append("Consider reducing parallel processing workers")
        
        if metrics['memory_percent'] > 85:
            recommendations.append("Implement memory pooling for large datasets")
        
        if metrics['disk_usage'] > 90:
            recommendations.append("Implement log rotation and cleanup")
        
        return recommendations

# Performance monitoring decorator
def monitor_performance(func):
    """Decorator to monitor function performance."""
    def wrapper(*args, **kwargs):
        start_time = time.time()
        start_memory = psutil.virtual_memory().used
        
        result = func(*args, **kwargs)
        
        end_time = time.time()
        end_memory = psutil.virtual_memory().used
        
        execution_time = end_time - start_time
        memory_used = end_memory - start_memory
        
        print(f"Function {func.__name__} executed in {execution_time:.4f}s, "
              f"Memory used: {memory_used / (1024*1024):.2f}MB")
        
        return result
    return wrapper
