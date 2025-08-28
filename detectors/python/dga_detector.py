#!/usr/bin/env python3
"""
DGA Detector for Goliath Systems

Analyzes Zeek DNS logs to detect potential Domain Generation Algorithm (DGA) domains
using entropy analysis, length scoring, and character distribution patterns.
"""

import argparse
import json
import math
import re
import sys
from collections import Counter
from typing import Dict, List, Tuple


class DGADetector:
    """Detects DGA domains using multiple scoring methods."""
    
    def __init__(self):
        self.suspicious_tlds = {'.xyz', '.top', '.club', '.online', '.site', '.tech'}
        self.common_words = {
            'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'ns1', 'ns2', 'dns',
            'api', 'cdn', 'web', 'app', 'dev', 'test', 'staging', 'prod'
        }
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(text.lower())
        text_length = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / text_length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def calculate_length_score(self, domain: str) -> float:
        """Score domain based on length characteristics."""
        # Remove TLD for analysis
        base_domain = domain.split('.')[0] if '.' in domain else domain
        
        # Ideal domain length is 8-15 characters
        ideal_length = 12
        length = len(base_domain)
        
        if length < 3:
            return 0.0  # Too short to be suspicious
        elif length > 50:
            return 1.0  # Suspiciously long
        
        # Calculate distance from ideal length
        distance = abs(length - ideal_length)
        max_distance = 50 - 3
        
        return min(1.0, distance / max_distance)
    
    def calculate_digit_score(self, domain: str) -> float:
        """Score domain based on digit patterns."""
        base_domain = domain.split('.')[0] if '.' in domain else domain
        
        if not base_domain:
            return 0.0
        
        # Count digits and calculate ratio
        digit_count = sum(1 for c in base_domain if c.isdigit())
        total_chars = len(base_domain)
        digit_ratio = digit_count / total_chars
        
        # High digit ratio is suspicious
        return digit_ratio
    
    def calculate_consonant_score(self, domain: str) -> float:
        """Score domain based on consonant patterns."""
        base_domain = domain.split('.')[0] if '.' in domain else domain
        
        if not base_domain:
            return 0.0
        
        consonants = set('bcdfghjklmnpqrstvwxyz')
        consonant_count = sum(1 for c in base_domain.lower() if c in consonants)
        total_chars = len(base_domain)
        consonant_ratio = consonant_count / total_chars
        
        # Very high consonant ratio can be suspicious
        return max(0.0, consonant_ratio - 0.6) * 2.5
    
    def calculate_base64_score(self, domain: str) -> float:
        """Detect potential base64-encoded domains."""
        base_domain = domain.split('.')[0] if '.' in domain else domain
        
        if not base_domain:
            return 0.0
        
        # Check for base64-like patterns (alphanumeric with = padding)
        base64_pattern = re.compile(r'^[A-Za-z0-9+/]+=*$')
        if base64_pattern.match(base_domain):
            return 0.8
        
        # Check for high entropy with base64-like character distribution
        if len(base_domain) >= 8:
            alphanumeric_ratio = sum(1 for c in base_domain if c.isalnum()) / len(base_domain)
            if alphanumeric_ratio > 0.95:
                return 0.6
        
        return 0.0
    
    def is_common_domain(self, domain: str) -> bool:
        """Check if domain contains common words."""
        base_domain = domain.split('.')[0] if '.' in domain else domain
        
        # Check for common words
        for word in self.common_words:
            if word in base_domain.lower():
                return True
        
        return False
    
    def analyze_domain(self, domain: str) -> Dict:
        """Analyze a single domain and return scoring details."""
        if not domain or domain == '-' or domain == '(empty)':
            return {
                'domain': domain,
                'score': 0.0,
                'scores': {},
                'classification': 'clean'
            }
        
        # Calculate individual scores
        entropy = self.calculate_entropy(domain)
        length_score = self.calculate_length_score(domain)
        digit_score = self.calculate_digit_score(domain)
        consonant_score = self.calculate_consonant_score(domain)
        base64_score = self.calculate_base64_score(domain)
        
        # Weight the scores
        weights = {
            'entropy': 0.3,
            'length': 0.2,
            'digits': 0.2,
            'consonants': 0.15,
            'base64': 0.15
        }
        
        # Normalize entropy (0-4.5 range to 0-1)
        normalized_entropy = min(1.0, entropy / 4.5)
        
        # Calculate weighted score
        weighted_score = (
            normalized_entropy * weights['entropy'] +
            length_score * weights['length'] +
            digit_score * weights['digits'] +
            consonant_score * weights['consonants'] +
            base64_score * weights['base64']
        )
        
        # Adjust score based on domain characteristics
        if self.is_common_domain(domain):
            weighted_score *= 0.3  # Reduce score for common domains
        
        # Check TLD
        if any(tld in domain.lower() for tld in self.suspicious_tlds):
            weighted_score *= 1.2  # Increase score for suspicious TLDs
        
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
        
        return {
            'domain': domain,
            'score': round(final_score, 3),
            'scores': {
                'entropy': round(entropy, 3),
                'length': round(length_score, 3),
                'digits': round(digit_score, 3),
                'consonants': round(consonant_score, 3),
                'base64': round(base64_score, 3)
            },
            'classification': classification
        }
    
    def process_zeek_log(self, log_file: str, output_file: str = None) -> List[Dict]:
        """Process Zeek DNS log file and return DGA analysis results."""
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
                        if len(fields) < 9:  # Minimum required fields
                            continue
                        
                        # Extract query field (index 8 in Zeek DNS log)
                        query = fields[8] if len(fields) > 8 else ''
                        
                        # Analyze domain
                        analysis = self.analyze_domain(query)
                        analysis['line_number'] = line_num
                        analysis['raw_line'] = line
                        
                        results.append(analysis)
                        
                    except Exception as e:
                        print(f"Error processing line {line_num}: {e}", file=sys.stderr)
                        continue
            
            # Sort by score (highest first)
            results.sort(key=lambda x: x['score'], reverse=True)
            
            # Output results
            if output_file:
                with open(output_file, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"Results saved to {output_file}")
            else:
                # Print high-risk domains
                high_risk = [r for r in results if r['score'] >= 0.6]
                if high_risk:
                    print(f"\nFound {len(high_risk)} suspicious domains:")
                    for result in high_risk[:10]:  # Show top 10
                        print(f"  {result['domain']} (Score: {result['score']}, Class: {result['classification']})")
                else:
                    print("No suspicious domains detected.")
            
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
        description="DGA Detector for Zeek DNS logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dga_detector.py --zeek dns.log
  python dga_detector.py --zeek dns.log --output results.json
  python dga_detector.py --zeek dns.log --threshold 0.7
        """
    )
    
    parser.add_argument(
        '--zeek', '-z',
        required=True,
        help='Zeek DNS log file to analyze'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output JSON file for results'
    )
    
    parser.add_argument(
        '--threshold', '-t',
        type=float,
        default=0.6,
        help='Score threshold for suspicious domains (default: 0.6)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    # Initialize detector
    detector = DGADetector()
    
    # Process log file
    print(f"Analyzing DNS log: {args.zeek}")
    results = detector.process_zeek_log(args.zeek, args.output)
    
    if not results:
        print("No results to display.")
        return
    
    # Display summary
    total_domains = len(results)
    suspicious_count = len([r for r in results if r['score'] >= args.threshold])
    
    print(f"\nAnalysis Summary:")
    print(f"  Total domains analyzed: {total_domains}")
    print(f"  Suspicious domains (≥{args.threshold}): {suspicious_count}")
    print(f"  Average score: {sum(r['score'] for r in results) / total_domains:.3f}")
    
    # Show top suspicious domains
    if suspicious_count > 0:
        print(f"\nTop suspicious domains:")
        for i, result in enumerate(results[:10], 1):
            if result['score'] >= args.threshold:
                print(f"  {i:2d}. {result['domain']:<30} Score: {result['score']:.3f} ({result['classification']})")
                
                if args.verbose:
                    scores = result['scores']
                    print(f"       Entropy: {scores['entropy']:.3f}, Length: {scores['length']:.3f}, "
                          f"Digits: {scores['digits']:.3f}, Consonants: {scores['consonants']:.3f}, "
                          f"Base64: {scores['base64']:.3f}")


if __name__ == '__main__':
    main()
