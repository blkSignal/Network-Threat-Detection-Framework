#!/usr/bin/env python3
"""
Comprehensive Test Runner for Goliath Systems

This script runs all test suites with different configurations:
- Unit tests
- Edge case tests
- Performance tests
- Load tests
- Security tests
- Integration tests
"""

import os
import sys
import subprocess
import time
import json
from datetime import datetime
import argparse

def run_command(cmd, description):
    """Run a command and return the result."""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"Command: {' '.join(cmd)}")
    print(f"{'='*60}")
    
    start_time = time.time()
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"Duration: {duration:.2f} seconds")
        print(f"Exit Code: {result.returncode}")
        
        if result.stdout:
            print("\nSTDOUT:")
            print(result.stdout)
        
        if result.stderr:
            print("\nSTDERR:")
            print(result.stderr)
        
        return {
            'success': result.returncode == 0,
            'duration': duration,
            'exit_code': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr
        }
        
    except Exception as e:
        print(f"Error running command: {e}")
        return {
            'success': False,
            'duration': 0,
            'exit_code': -1,
            'stdout': '',
            'stderr': str(e)
        }

def run_unit_tests():
    """Run basic unit tests."""
    return run_command(
        ['python3', '-m', 'pytest', 'test_detectors.py', '-v', '--tb=short'],
        "Unit Tests"
    )

def run_edge_case_tests():
    """Run edge case tests."""
    return run_command(
        ['python3', '-m', 'pytest', 'test_edge_cases.py', '-v', '--tb=short'],
        "Edge Case Tests"
    )

def run_performance_tests():
    """Run performance tests."""
    return run_command(
        ['python3', '-m', 'pytest', 'test_performance.py', '-v', '--tb=short'],
        "Performance Tests"
    )

def run_security_tests():
    """Run security-focused tests."""
    return run_command(
        ['python3', '-m', 'pytest', 'test_edge_cases.py::TestSecurityEdgeCases', '-v', '--tb=short'],
        "Security Tests"
    )

def run_load_tests():
    """Run load testing."""
    return run_command(
        ['python3', '-m', 'pytest', 'test_performance.py::TestLoadTesting', '-v', '--tb=short'],
        "Load Tests"
    )

def run_stress_tests():
    """Run stress testing."""
    return run_command(
        ['python3', '-m', 'pytest', 'test_edge_cases.py::TestStressTesting', '-v', '--tb=short'],
        "Stress Tests"
    )

def run_integration_tests():
    """Run integration tests."""
    return run_command(
        ['python3', '-m', 'pytest', 'test_detectors.py::TestIntegration', '-v', '--tb=short'],
        "Integration Tests"
    )

def run_coverage_tests():
    """Run tests with coverage."""
    return run_command(
        ['python3', '-m', 'pytest', '--cov=../detectors/python', '--cov=../api', '--cov-report=term-missing', '--cov-report=html'],
        "Coverage Tests"
    )

def run_benchmark_tests():
    """Run benchmark tests."""
    return run_command(
        ['python3', '-m', 'pytest', 'test_performance.py::TestPerformanceBenchmarks', '-v', '--benchmark-only'],
        "Benchmark Tests"
    )

def run_all_tests():
    """Run all test suites."""
    return run_command(
        ['python3', '-m', 'pytest', '-v', '--tb=short'],
        "All Tests"
    )

def generate_report(results):
    """Generate a test execution report."""
    report = {
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total_tests': len(results),
            'passed': sum(1 for r in results.values() if r['success']),
            'failed': sum(1 for r in results.values() if not r['success']),
            'total_duration': sum(r['duration'] for r in results.values())
        },
        'results': results
    }
    
    print(f"\n{'='*60}")
    print("TEST EXECUTION SUMMARY")
    print(f"{'='*60}")
    print(f"Total Test Suites: {report['summary']['total_tests']}")
    print(f"Passed: {report['summary']['passed']}")
    print(f"Failed: {report['summary']['failed']}")
    print(f"Total Duration: {report['summary']['total_duration']:.2f} seconds")
    print(f"Success Rate: {(report['summary']['passed']/report['summary']['total_tests']*100):.1f}%")
    
    print(f"\nDetailed Results:")
    for test_name, result in results.items():
        status = "PASS" if result['success'] else "FAIL"
        print(f"  {test_name:<20} {status:<4} {result['duration']:6.2f}s")
    
    # Save report to file
    report_file = f"test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nDetailed report saved to: {report_file}")
    
    return report

def main():
    """Main test runner."""
    parser = argparse.ArgumentParser(description="Comprehensive Test Runner for Goliath Systems")
    parser.add_argument('--suite', choices=[
        'unit', 'edge', 'performance', 'security', 'load', 'stress', 
        'integration', 'coverage', 'benchmark', 'all'
    ], default='all', help='Test suite to run')
    
    parser.add_argument('--quick', action='store_true', help='Run only quick tests')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--save-report', action='store_true', help='Save detailed report')
    
    args = parser.parse_args()
    
    print("Goliath Systems - Comprehensive Test Runner")
    print("=" * 60)
    
    # Define test suites
    test_suites = {
        'unit': run_unit_tests,
        'edge': run_edge_case_tests,
        'performance': run_performance_tests,
        'security': run_security_tests,
        'load': run_load_tests,
        'stress': run_stress_tests,
        'integration': run_integration_tests,
        'coverage': run_coverage_tests,
        'benchmark': run_benchmark_tests,
        'all': run_all_tests
    }
    
    # Quick test mode - skip slow tests
    if args.quick:
        print("Quick test mode - skipping slow tests")
        test_suites = {
            'unit': run_unit_tests,
            'edge': run_edge_case_tests,
            'integration': run_integration_tests
        }
    
    # Run selected test suite
    if args.suite == 'all':
        results = {}
        for name, func in test_suites.items():
            if name != 'all':
                results[name] = func()
    else:
        results = {args.suite: test_suites[args.suite]()}
    
    # Generate report
    if args.save_report or args.suite == 'all':
        report = generate_report(results)
        
        # Exit with error if any tests failed
        if report['summary']['failed'] > 0:
            print(f"\n❌ {report['summary']['failed']} test suite(s) failed!")
            sys.exit(1)
        else:
            print(f"\n✅ All test suites passed!")
    else:
        # Simple output for single suite
        for name, result in results.items():
            if result['success']:
                print(f"\n✅ {name} tests passed in {result['duration']:.2f}s")
            else:
                print(f"\n❌ {name} tests failed in {result['duration']:.2f}s")
                sys.exit(1)

if __name__ == '__main__':
    main()
