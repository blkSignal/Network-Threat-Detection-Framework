-- Initialize ClickHouse database for Goliath Systems
-- This script runs when the ClickHouse container starts

-- Create database
CREATE DATABASE IF NOT EXISTS goliath;

-- Use the database
USE goliath;

-- Create table for Zeek DNS logs
CREATE TABLE IF NOT EXISTS zeek_dns (
    ts DateTime64(3),
    uid String,
    id_orig_h IPv4,
    id_orig_p UInt16,
    id_resp_h IPv4,
    id_resp_p UInt16,
    proto Enum8('udp' = 1, 'tcp' = 2),
    trans_id UInt16,
    rtt Float32,
    query String,
    qclass UInt16,
    qclass_name String,
    qtype UInt16,
    qtype_name String,
    rcode UInt16,
    rcode_name String,
    AA Bool,
    TC Bool,
    RD Bool,
    RA Bool,
    Z UInt8,
    answers Array(String),
    TTLs Array(Float32),
    rejected Bool,
    insert_ts DateTime DEFAULT now()
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, uid)
TTL ts + INTERVAL 90 DAY;

-- Create table for Zeek connection logs
CREATE TABLE IF NOT EXISTS zeek_conn (
    ts DateTime64(3),
    uid String,
    id_orig_h IPv4,
    id_orig_p UInt16,
    id_resp_h IPv4,
    id_resp_p UInt16,
    proto Enum8('tcp' = 1, 'udp' = 2, 'icmp' = 3),
    service String,
    duration Float32,
    orig_bytes UInt64,
    resp_bytes UInt64,
    conn_state String,
    local_orig Bool,
    local_resp Bool,
    missed_bytes UInt64,
    history String,
    orig_pkts UInt64,
    orig_ip_bytes UInt64,
    resp_pkts UInt64,
    resp_ip_bytes UInt64,
    tunnel_parents Array(String),
    insert_ts DateTime DEFAULT now()
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, uid)
TTL ts + INTERVAL 90 DAY;

-- Create table for Suricata EVE logs
CREATE TABLE IF NOT EXISTS suricata_events (
    ts DateTime64(3),
    event_type String,
    src_ip IPv4,
    dest_ip IPv4,
    src_port UInt16,
    dest_port UInt16,
    protocol String,
    alert_signature String,
    alert_category String,
    alert_severity UInt8,
    flow_id UInt64,
    pcap_file String,
    insert_ts DateTime DEFAULT now()
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, event_type)
TTL ts + INTERVAL 90 DAY;

-- Create table for detector results
CREATE TABLE IF NOT EXISTS detector_results (
    ts DateTime64(3),
    detector_type Enum8('dga' = 1, 'beacon' = 2),
    source_ip IPv4,
    destination_ip IPv4,
    score Float32,
    details String,
    insert_ts DateTime DEFAULT now()
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, detector_type, score)
TTL ts + INTERVAL 90 DAY;

-- Create views for common queries
CREATE VIEW IF NOT EXISTS top_dga_domains AS
SELECT 
    query,
    count() as count,
    avg(score) as avg_score
FROM detector_results dr
JOIN zeek_dns zd ON dr.source_ip = zd.id_orig_h
WHERE detector_type = 'dga'
GROUP BY query
ORDER BY count DESC, avg_score DESC;

CREATE VIEW IF NOT EXISTS beacon_candidates AS
SELECT 
    source_ip,
    destination_ip,
    score,
    details
FROM detector_results
WHERE detector_type = 'beacon' AND score >= 0.7
ORDER BY score DESC;

-- Insert sample data for testing
INSERT INTO detector_results (ts, detector_type, source_ip, destination_ip, score, details) VALUES
(now(), 'dga', toIPv4('192.168.1.100'), toIPv4('8.8.8.8'), 0.85, 'High entropy domain: x7k9m2n4p8q1r3s5t6u7v8w9x0y1z2.com'),
(now(), 'beacon', toIPv4('192.168.1.101'), toIPv4('10.0.0.1'), 0.78, 'Regular intervals detected: 300s ± 5s');
