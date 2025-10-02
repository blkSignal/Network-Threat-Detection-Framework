# Network-Threat-Detection-Framework

**Intent**: Goliath Systems proves you can design, deploy, and analyze a modern network-threat detection pipeline that still works when payloads are encrypted.

- **Real NIDS ops**: Suricata + Zeek, custom rules, log handling
- **Data plumbing**: logs → ClickHouse → Grafana dashboards  
- **Detection engineering**: behavioral analytics (DGA/exfil, beaconing) on Zeek logs
- **Engineering maturity**: Docker Compose, clean repo, unit tests, reproducible demo

## Architecture

```
Network Traffic → Zeek + Suricata → ClickHouse → Grafana
                     ↓
              Custom Detectors (Python)
                     ↓
              Behavioral Analytics
```

## Quick Start

```bash
# Clone and setup
git clone https://github.com/<you>/goliath-systems && cd goliath-systems
docker compose up -d

# Fetch sample PCAPs (not committed to repo)
bash scripts/fetch_pcaps.sh

# Parse PCAPs to generate logs
zeek -r data/pcaps/sample.pcap
suricata -r data/pcaps/sample.pcap -l data/suricata --set outputs.eve-log.enabled=yes

# Run threat detectors
python detectors/python/dga_detector.py --zeek dns.log
python detectors/python/beacon_detector.py --zeek conn.log

# View dashboards
# Open http://localhost:3000 and import dashboard JSONs
```

## Components

### Sensors
- **Zeek**: DNS/connection logs, JA3/JA4/HASSH fingerprinting
- **Suricata**: EVE logs, custom local.rules for signature detection

### Pipeline
- **Dockerized services** for easy deployment
- **ClickHouse** for high-performance log storage and querying
- **Grafana** for visualization and dashboards

### Detectors
- **dga_detector.py**: Entropy/length/digit/base64 scoring on DNS logs
- **beacon_detector.py**: Inter-arrival variance scoring on connection logs

### Testing
- **pytest** validates beacon scoring (periodic vs random)
- **Unit tests** ensure detector reliability

## Success Checklist

- [ ] Detectors output ≥1 DGA hit and ≥1 beacon candidate (score ≥ 0.7) on demo pcap
- [ ] Grafana shows panels for top entropy domains & Suricata alerts
- [ ] pytest passes
- [ ] Fresh clone → docker compose up -d works end-to-end

## License

MIT License - see LICENSE file for details
