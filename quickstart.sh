#!/bin/bash
# Goliath Systems - Quick Start Script
# Automates the initial setup and testing of the detection pipeline

set -e

echo "🚀 Goliath Systems - Quick Start"
echo "=================================="
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if Docker Compose is available
if ! command -v docker compose > /dev/null 2>&1; then
    echo "❌ Docker Compose is not available. Please install Docker Compose and try again."
    exit 1
fi

echo "✅ Docker environment ready"
echo ""

# Create necessary directories
echo "📁 Creating project directories..."
mkdir -p data/zeek data/suricata data/pcaps
echo "✅ Directories created"
echo ""

# Start the services
echo "🐳 Starting Goliath Systems services..."
docker compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 30

# Check service status
echo "🔍 Checking service status..."
if docker compose ps | grep -q "Up"; then
    echo "✅ Services are running"
else
    echo "❌ Some services failed to start"
    docker compose logs --tail=20
    exit 1
fi

echo ""
echo "📊 Service Status:"
docker compose ps
echo ""

# Test ClickHouse connection
echo "🗄️  Testing ClickHouse connection..."
if docker exec goliath-clickhouse clickhouse-client --user goliath --password goliath123 --query "SELECT 1" > /dev/null 2>&1; then
    echo "✅ ClickHouse is accessible"
else
    echo "❌ ClickHouse connection failed"
    exit 1
fi

# Test Grafana
echo "📈 Testing Grafana..."
if curl -s http://localhost:3000 > /dev/null; then
    echo "✅ Grafana is accessible at http://localhost:3000"
    echo "   Username: admin"
    echo "   Password: goliath123"
else
    echo "❌ Grafana is not accessible"
fi

echo ""
echo "🎯 Next Steps:"
echo "==============="
echo ""
echo "1. 📥 Add PCAP files to data/pcaps/ directory"
echo "   bash scripts/fetch_pcaps.sh"
echo ""
echo "2. 🔍 Process PCAPs with Zeek:"
echo "   docker exec goliath-zeek zeek -r /pcaps/your_file.pcap"
echo ""
echo "3. 🚨 Process PCAPs with Suricata:"
echo "   docker exec goliath-suricata suricata -r /pcaps/your_file.pcap -l /var/log/suricata"
echo ""
echo "4. 🐍 Run threat detectors:"
echo "   python detectors/python/dga_detector.py --zeek dns.log"
echo "   python detectors/python/beacon_detector.py --zeek conn.log"
echo ""
echo "5. 📊 View dashboards:"
echo "   Open http://localhost:3000 in your browser"
echo ""
echo "6. 🧪 Run tests:"
echo "   python -m pytest tests/"
echo ""
echo "🎉 Goliath Systems is ready!"
echo ""
echo "📚 Documentation: docs/architecture.md"
echo "🐛 Issues: Check docker compose logs for troubleshooting"
echo ""
echo "Happy threat hunting! 🕵️‍♂️"
