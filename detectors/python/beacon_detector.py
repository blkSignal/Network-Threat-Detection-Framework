#!/usr/bin/env python3
"""
Beacon Detector for Goliath Systems

Analyzes Zeek connection logs to detect potential beaconing behavior
using inter-arrival time analysis and periodicity detection.
"""

import argparse
import json
import math
import statistics
import sys
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional


class BeaconDetector:
    """Detects beaconing behavior using inter-arrival time analysis."""
    
    def __init__(self, window_size: int = 100, min_connections: int = 5):
        self.window_size = window_size
        self.min_connections = min_connections
        
        # Store connection timestamps for each flow
        self.flow_timestamps = defaultdict(lambda: deque(maxlen=window_size))
        
        # Beacon detection thresholds
        self.periodicity_threshold = 0.7
        self.variance_threshold = 0.3
        self.min_interval = 30  # Minimum seconds between connections
        self.max_interval = 3600  # Maximum seconds between connections
    
    def parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse Zeek timestamp string to datetime object."""
        try:
            # Zeek timestamps are Unix epoch with microsecond precision
            ts_float = float(ts_str)
            return datetime.fromtimestamp(ts_float)
        except (ValueError, TypeError):
            return None
    
    def calculate_intervals(self, timestamps: List[datetime]) -> List[float]:
        """Calculate inter-arrival times between consecutive timestamps."""
        if len(timestamps) < 2:
            return []
        
        intervals = []
        for i in range(1, len(timestamps)):
            interval = (timestamps[i] - timestamps[i-1]).total_seconds()
            intervals.append(interval)
        
        return intervals
    
    def calculate_periodicity_score(self, intervals: List[float]) -> float:
        """Calculate periodicity score based on interval consistency."""
        if len(intervals) < 2:
            return 0.0
        
        # Calculate mean interval
        mean_interval = statistics.mean(intervals)
        
        if mean_interval < self.min_interval or mean_interval > self.max_interval:
            return 0.0
        
        # Calculate coefficient of variation (CV = std/mean)
        try:
            std_dev = statistics.stdev(intervals)
            cv = std_dev / mean_interval if mean_interval > 0 else float('inf')
        except statistics.StatisticsError:
            return 0.0
        
        # Lower CV indicates more periodic behavior
        # Convert to 0-1 scale where 1 is perfectly periodic
        periodicity = max(0.0, 1.0 - min(1.0, cv))
        
        return periodicity
    
    def calculate_variance_score(self, intervals: List[float]) -> float:
        """Calculate variance score based on interval distribution."""
        if len(intervals) < 2:
            return 0.0
        
        # Calculate variance of intervals
        try:
            variance = statistics.variance(intervals)
        except statistics.StatisticsError:
            return 0.0
        
        # Normalize variance (0 = no variance, 1 = high variance)
        # Use log scale to handle wide range of values
        if variance > 0:
            normalized_variance = min(1.0, math.log10(variance + 1) / 3)
        else:
            normalized_variance = 0.0
        
        # Lower variance is more suspicious (more regular)
        variance_score = 1.0 - normalized_variance
        
        return variance_score
    
    def calculate_entropy_score(self, intervals: List[float]) -> float:
        """Calculate entropy score based on interval distribution."""
        if len(intervals) < 2:
            return 0.0
        
        # Discretize intervals into bins for entropy calculation
        min_interval = min(intervals)
        max_interval = max(intervals)
        
        if max_interval == min_interval:
            return 0.0  # All intervals are the same
        
        # Create 10 bins
        num_bins = 10
        bin_size = (max_interval - min_interval) / num_bins
        
        if bin_size == 0:
            return 0.0
        
        # Count intervals in each bin
        bins = [0] * num_bins
        for interval in intervals:
            bin_index = min(int((interval - min_interval) / bin_size), num_bins - 1)
            bins[bin_index] += 1
        
        # Calculate entropy
        total = len(intervals)
        entropy = 0.0
        for count in bins:
            if count > 0:
                probability = count / total
                entropy -= probability * math.log2(probability)
        
        # Normalize entropy (0 = low entropy/regular, 1 = high entropy/irregular)
        max_entropy = math.log2(num_bins)
        normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0
        
        # Lower entropy is more suspicious (more regular)
        entropy_score = 1.0 - normalized_entropy
        
        return entropy_score
    
    def detect_beaconing(self, flow_key: str, timestamps: List[datetime]) -> Dict:
        """Detect beaconing behavior for a specific flow."""
        if len(timestamps) < self.min_connections:
            return {
                'flow_key': flow_key,
                'score': 0.0,
                'classification': 'insufficient_data',
                'details': f"Only {len(timestamps)} connections (need {self.min_connections})"
            }
        
        # Sort timestamps chronologically
        sorted_timestamps = sorted(timestamps)
        
        # Calculate inter-arrival intervals
        intervals = self.calculate_intervals(sorted_timestamps)
        
        if not intervals:
            return {
                'flow_key': flow_key,
                'score': 0.0,
                'classification': 'insufficient_data',
                'details': "No intervals to analyze"
            }
        
        # Calculate individual scores
        periodicity_score = self.calculate_periodicity_score(intervals)
        variance_score = self.calculate_variance_score(intervals)
        entropy_score = self.calculate_entropy_score(intervals)
        
        # Weight the scores
        weights = {
            'periodicity': 0.4,
            'variance': 0.3,
            'entropy': 0.3
        }
        
        # Calculate weighted score
        weighted_score = (
            periodicity_score * weights['periodicity'] +
            variance_score * weights['variance'] +
            entropy_score * weights['entropy']
        )
        
        # Additional factors
        connection_count_bonus = min(0.1, len(timestamps) / 100)  # Bonus for more connections
        weighted_score += connection_count_bonus
        
        # Cap score at 1.0
        final_score = min(1.0, weighted_score)
        
        # Classification
        if final_score >= 0.8:
            classification = 'high_risk'
        elif final_score >= 0.6:
            classification = 'medium_risk'
        elif final_score >= 0.4:
            classification = 'low_risk'
        else:
            classification = 'clean'
        
        # Generate details
        mean_interval = statistics.mean(intervals)
        std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0
        
        details = (
            f"Connections: {len(timestamps)}, "
            f"Mean interval: {mean_interval:.1f}s ± {std_dev:.1f}s, "
            f"Periodicity: {periodicity_score:.3f}, "
            f"Variance: {variance_score:.3f}, "
            f"Entropy: {entropy_score:.3f}"
        )
        
        return {
            'flow_key': flow_key,
            'score': round(final_score, 3),
            'classification': classification,
            'details': details,
            'metrics': {
                'connection_count': len(timestamps),
                'mean_interval': round(mean_interval, 2),
                'std_dev': round(std_dev, 2),
                'periodicity_score': round(periodicity_score, 3),
                'variance_score': round(variance_score, 3),
                'entropy_score': round(entropy_score, 3)
            }
        }
    
    def process_zeek_log(self, log_file: str, output_file: str = None) -> List[Dict]:
        """Process Zeek connection log file and return beaconing analysis results."""
        results = []
        
        try:
            with open(log_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    try:
                        # Parse Zeek log format (tab-separated)
                        fields = line.split('\t')
                        if len(fields) < 7:  # Minimum required fields
                            continue
                        
                        # Extract fields (Zeek conn.log format)
                        ts = fields[0]  # timestamp
                        uid = fields[1]  # connection UID
                        id_orig_h = fields[2]  # originator IP
                        id_orig_p = fields[3]  # originator port
                        id_resp_h = fields[4]  # responder IP
                        id_resp_p = fields[5]  # responder port
                        proto = fields[6]  # protocol
                        
                        # Skip non-TCP connections (beaconing is typically TCP)
                        if proto != 'tcp':
                            continue
                        
                        # Parse timestamp
                        timestamp = self.parse_timestamp(ts)
                        if not timestamp:
                            continue
                        
                        # Create flow key (source -> destination)
                        flow_key = f"{id_orig_h}:{id_orig_p} -> {id_resp_h}:{id_resp_p}"
                        
                        # Store timestamp for this flow
                        self.flow_timestamps[flow_key].append(timestamp)
                        
                    except Exception as e:
                        print(f"Error processing line {line_num}: {e}", file=sys.stderr)
                        continue
            
            # Analyze each flow for beaconing behavior
            for flow_key, timestamps in self.flow_timestamps.items():
                if len(timestamps) >= self.min_connections:
                    analysis = self.detect_beaconing(flow_key, list(timestamps))
                    results.append(analysis)
            
            # Sort by score (highest first)
            results.sort(key=lambda x: x['score'], reverse=True)
            
            # Output results
            if output_file:
                with open(output_file, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"Results saved to {output_file}")
            else:
                # Print high-risk flows
                high_risk = [r for r in results if r['score'] >= 0.6]
                if high_risk:
                    print(f"\nFound {len(high_risk)} suspicious flows:")
                    for result in high_risk[:10]:  # Show top 10
                        print(f"  {result['flow_key']} (Score: {result['score']}, Class: {result['classification']})")
                else:
                    print("No suspicious flows detected.")
            
            return results
            
        except FileNotFoundError:
            print(f"Error: Log file '{log_file}' not found.", file=sys.stderr)
            return []
        except Exception as e:
            print(f"Error processing log file: {e}", file=sys.stderr)
            return []


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Beacon Detector for Zeek connection logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python beacon_detector.py --zeek conn.log
  python beacon_detector.py --zeek conn.log --output results.json
  python beacon_detector.py --zeek conn.log --threshold 0.7
        """
    )
    
    parser.add_argument(
        '--zeek', '-z',
        required=True,
        help='Zeek connection log file to analyze'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output JSON file for results'
    )
    
    parser.add_argument(
        '--threshold', '-t',
        type=float,
        default=0.6,
        help='Score threshold for suspicious flows (default: 0.6)'
    )
    
    parser.add_argument(
        '--min-connections', '-m',
        type=int,
        default=5,
        help='Minimum connections required for analysis (default: 5)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    # Initialize detector
    detector = BeaconDetector(min_connections=args.min_connections)
    
    # Process log file
    print(f"Analyzing connection log: {args.zeek}")
    results = detector.process_zeek_log(args.zeek, args.output)
    
    if not results:
        print("No results to display.")
        return
    
    # Display summary
    total_flows = len(results)
    suspicious_count = len([r for r in results if r['score'] >= args.threshold])
    
    print(f"\nAnalysis Summary:")
    print(f"  Total flows analyzed: {total_flows}")
    print(f"  Suspicious flows (≥{args.threshold}): {suspicious_count}")
    print(f"  Average score: {sum(r['score'] for r in results) / total_flows:.3f}")
    
    # Show top suspicious flows
    if suspicious_count > 0:
        print(f"\nTop suspicious flows:")
        for i, result in enumerate(results[:10], 1):
            if result['score'] >= args.threshold:
                print(f"  {i:2d}. {result['flow_key']:<40} Score: {result['score']:.3f} ({result['classification']})")
                
                if args.verbose:
                    metrics = result['metrics']
                    print(f"       Connections: {metrics['connection_count']}, "
                          f"Interval: {metrics['mean_interval']}s ± {metrics['std_dev']}s")


if __name__ == '__main__':
    main()
