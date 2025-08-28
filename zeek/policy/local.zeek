# Goliath Systems - Custom Zeek Policy
# This policy enhances logging and enables additional fingerprinting

# Load required packages
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/conn

# Enable JA3/JA4 fingerprinting for TLS connections
@load policy/protocols/ssl/ja3
@load policy/protocols/ssl/ja4

# Enable HASSH fingerprinting for SSH connections
@load policy/protocols/ssh/hassh

# Custom logging for enhanced threat detection
module GoliathSystems;

export {
    # Custom log for suspicious DNS queries
    redef enum Log::ID += { SUSPICIOUS_DNS };
    
    type SuspiciousDNSInfo: record {
        ts: time;
        uid: string;
        id_orig_h: addr;
        id_resp_h: addr;
        query: string;
        entropy: double;
        length: count;
        digit_ratio: double;
        score: double;
    };
}

# Log suspicious DNS queries
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    # Calculate entropy and other metrics
    local entropy = calculate_entropy(query);
    local length = |query|;
    local digit_count = 0;
    
    for (i in query) {
        if (query[i] >= "0" && query[i] <= "9") {
            digit_count += 1;
        }
    }
    
    local digit_ratio = digit_count / length;
    local score = (entropy / 4.5) * 0.4 + (length / 50.0) * 0.3 + digit_ratio * 0.3;
    
    # Log if score is above threshold
    if (score > 0.6) {
        local info: SuspiciousDNSInfo = [
            $ts = network_time(),
            $uid = c$uid,
            $id_orig_h = c$id$orig_h,
            $id_resp_h = c$id$resp_h,
            $query = query,
            $entropy = entropy,
            $length = length,
            $digit_ratio = digit_ratio,
            $score = score
        ];
        
        Log::write(SuspiciousDNSInfo::SUSPICIOUS_DNS, info);
    }
}

# Calculate Shannon entropy
function calculate_entropy(text: string): double
{
    local char_counts: table[string] of count = table();
    local total = |text|;
    
    if (total == 0) {
        return 0.0;
    }
    
    # Count character frequencies
    for (i in text) {
        local char = text[i];
        if (char in char_counts) {
            char_counts[char] += 1;
        } else {
            char_counts[char] = 1;
        }
    }
    
    # Calculate entropy
    local entropy = 0.0;
    for (char in char_counts) {
        local probability = char_counts[char] / total;
        entropy -= probability * log(probability) / log(2.0);
    }
    
    return entropy;
}

# Enhanced connection logging
event connection_state_remove(c: connection)
{
    # Log connections with unusual patterns
    if (c$conn$duration > 300.0 && c$conn$orig_bytes > 1000000) {
        local info = [
            $ts = network_time(),
            $uid = c$uid,
            $id_orig_h = c$id$orig_h,
            $id_orig_p = c$id$orig_p,
            $id_resp_h = c$id$resp_h,
            $id_resp_p = c$id$resp_p,
            $proto = c$conn$proto,
            $duration = c$conn$duration,
            $orig_bytes = c$conn$orig_bytes,
            $resp_bytes = c$conn$resp_bytes
        ];
        
        Log::write(Conn::LOG, info);
    }
}

# Initialize logging
event zeek_init()
{
    Log::create_stream(GoliathSystems::SuspiciousDNSInfo::SUSPICIOUS_DNS, [
        $columns = SuspiciousDNSInfo,
        $path = "suspicious_dns"
    ]);
}
