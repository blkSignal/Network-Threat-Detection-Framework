# Goliath Systems - Architecture Documentation

## System Overview

Goliath Systems is a network threat detection pipeline designed to identify malicious activity in encrypted network traffic using behavioral analysis and signature-based detection. The system combines multiple detection approaches to provide comprehensive threat visibility.

## Architecture Diagram

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Network       │    │   Zeek          │    │   Suricata      │
│   Traffic       │───▶│   (DNS/Conn)    │    │   (EVE/Alerts)  │
│   (PCAP)       │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌─────────────────────────────────────────┐
                       │           ClickHouse                   │
                       │         (Log Storage)                  │
                       └─────────────────────────────────────────┘
                                │
                                ▼
                       ┌─────────────────────────────────────────┐
                       │        Python Detectors                │
                       │  ┌─────────────┐ ┌─────────────────┐  │
                       │  │ DGA         │ │ Beacon          │  │
                       │  │ Detector    │ │ Detector        │  │
                       │  └─────────────┘ └─────────────────┘  │
                       └─────────────────────────────────────────┘
                                │
                                ▼
                       ┌─────────────────────────────────────────┐
                       │           Grafana                      │
                       │        (Dashboards)                    │
                       └─────────────────────────────────────────┘
```

## Component Details

### 1. Network Sensors

#### Zeek (Bro)
- **Purpose**: Network traffic analysis and protocol parsing
- **Outputs**: 
  - `dns.log`: DNS query analysis
  - `conn.log`: Connection metadata
  - `ssl.log`: TLS/SSL fingerprinting (JA3/JA4)
  - `ssh.log`: SSH fingerprinting (HASSH)
- **Custom Policy**: Enhanced logging for suspicious patterns
- **Key Features**:
  - Real-time traffic analysis
  - Protocol-specific logging
  - Custom event generation

#### Suricata
- **Purpose**: Signature-based intrusion detection
- **Outputs**: 
  - `eve.json`: Event logs in JSON format
  - `fast.log`: Traditional alert format
- **Custom Rules**: Local rules for specific threat patterns
- **Key Features**:
  - Pattern matching
  - Protocol analysis
  - Alert correlation

### 2. Data Storage

#### ClickHouse
- **Purpose**: High-performance log storage and analytics
- **Schema Design**:
  - Partitioned by month for efficient querying
  - Optimized for time-series data
  - TTL-based data retention (90 days)
- **Tables**:
  - `zeek_dns`: DNS query logs
  - `zeek_conn`: Connection logs
  - `suricata_events`: Suricata alerts
  - `detector_results`: Analysis results
- **Views**:
  - `top_dga_domains`: Aggregated DGA findings
  - `beacon_candidates`: Beacon detection results

### 3. Threat Detectors

#### DGA Detector
- **Algorithm**: Multi-factor scoring system
- **Features**:
  - Shannon entropy calculation
  - Length-based scoring
  - Digit ratio analysis
  - Consonant pattern detection
  - Base64 encoding detection
- **Scoring Weights**:
  - Entropy: 30%
  - Length: 20%
  - Digits: 20%
  - Consonants: 15%
  - Base64: 15%
- **Output**: JSON with detailed scoring breakdown

#### Beacon Detector
- **Algorithm**: Inter-arrival time analysis
- **Features**:
  - Periodicity detection
  - Variance analysis
  - Entropy-based scoring
  - Connection count bonuses
- **Scoring Weights**:
  - Periodicity: 40%
  - Variance: 30%
  - Entropy: 30%
- **Output**: JSON with flow analysis and metrics

### 4. Visualization

#### Grafana
- **Purpose**: Real-time threat monitoring and analysis
- **Dashboards**:
  - DGA Detection Results
  - Beacon Detection Candidates
  - Threat Timeline
  - Suricata Alerts by Severity
  - Top Source IPs
  - Detection Score Distribution
- **Data Sources**: ClickHouse integration
- **Features**: Auto-refresh, drill-down capabilities

## Data Flow

### 1. Ingestion Phase
```
PCAP Files → Zeek/Suricata → Structured Logs → ClickHouse
```

### 2. Analysis Phase
```
ClickHouse Logs → Python Detectors → Threat Scores → ClickHouse Results
```

### 3. Visualization Phase
```
ClickHouse Results → Grafana Queries → Real-time Dashboards
```

## Security Considerations

### Data Privacy
- PCAP files are not committed to version control
- Log data includes TTL-based retention
- Sensitive IP addresses can be anonymized

### Access Control
- Docker containers run in isolated networks
- Database credentials are environment-specific
- Grafana access is password-protected

### Threat Handling
- Detectors run in isolated Python environments
- Malicious samples are not stored permanently
- Analysis results are sanitized

## Performance Characteristics

### Scalability
- ClickHouse handles millions of records efficiently
- Partitioned tables enable parallel processing
- Docker containers can be scaled horizontally

### Latency
- Real-time processing with Zeek/Suricata
- Batch processing for historical analysis
- Sub-second query response times

### Resource Usage
- Memory: ~2GB per container
- CPU: Variable based on traffic volume
- Storage: Configurable retention policies

## Deployment Options

### Development
- Single Docker Compose setup
- Local file processing
- Manual PCAP analysis

### Production
- Multi-node ClickHouse cluster
- Load-balanced Zeek instances
- Automated PCAP ingestion
- Alert forwarding to SIEM

## Monitoring and Maintenance

### Health Checks
- Container status monitoring
- Database connectivity verification
- Detector execution validation

### Log Management
- Structured logging throughout
- Error tracking and alerting
- Performance metrics collection

### Backup and Recovery
- ClickHouse data replication
- Configuration version control
- Disaster recovery procedures

## Future Enhancements

### Machine Learning
- Anomaly detection models
- Behavioral profiling
- Threat intelligence integration

### Automation
- Automated response actions
- Threat hunting workflows
- Incident response playbooks

### Integration
- SIEM system integration
- Threat intelligence feeds
- Security orchestration platforms
