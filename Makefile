# Goliath Systems - Makefile
# Common commands for project management

.PHONY: help start stop restart logs clean test install-deps run-detectors

# Default target
help:
	@echo "Goliath Systems - Available Commands"
	@echo "===================================="
	@echo ""
	@echo "Infrastructure:"
	@echo "  start          - Start all services with docker compose"
	@echo "  stop           - Stop all services"
	@echo "  restart        - Restart all services"
	@echo "  logs           - Show service logs"
	@echo "  clean          - Remove containers and volumes"
	@echo ""
	@echo "Development:"
	@echo "  install-deps   - Install Python dependencies"
	@echo "  test           - Run unit tests"
	@echo "  run-detectors  - Run both DGA and beacon detectors on sample data"
	@echo ""
	@echo "Quick Start:"
	@echo "  quickstart     - Run the automated setup script"
	@echo ""

# Start services
start:
	@echo "Starting Goliath Systems..."
	docker compose up -d
	@echo "Services started. Check status with: make logs"

# Stop services
stop:
	@echo "Stopping Goliath Systems..."
	docker compose down
	@echo "Services stopped"

# Restart services
restart: stop start

# Show logs
logs:
	docker compose logs -f

# Clean up
clean:
	@echo "Cleaning up containers and volumes..."
	docker compose down -v --remove-orphans
	docker system prune -f
	@echo "Cleanup complete"

# Install Python dependencies
install-deps:
	@echo "Installing Python dependencies..."
	pip install -r requirements.txt
	@echo "Dependencies installed"

# Run tests
test:
	@echo "Running unit tests..."
	python -m pytest tests/ -v
	@echo "Tests completed"

# Run detectors on sample data
run-detectors:
	@echo "Running threat detectors..."
	@echo "Note: This requires Zeek logs. Process a PCAP first:"
	@echo "  docker exec goliath-zeek zeek -r /pcaps/your_file.pcap"
	@echo ""
	@if [ -f "dns.log" ]; then \
		echo "Running DGA detector..."; \
		python detectors/python/dga_detector.py --zeek dns.log; \
	else \
		echo "dns.log not found. Process a PCAP first."; \
	fi
	@if [ -f "conn.log" ]; then \
		echo "Running beacon detector..."; \
		python detectors/python/beacon_detector.py --zeek conn.log; \
	else \
		echo "conn.log not found. Process a PCAP first."; \
	fi

# Quick start
quickstart:
	@echo "Running quick start script..."
	./quickstart.sh

# Show service status
status:
	@echo "Service Status:"
	docker compose ps

# Access ClickHouse
clickhouse:
	@echo "Accessing ClickHouse..."
	docker exec -it goliath-clickhouse clickhouse-client --user goliath --password goliath123

# Access Grafana
grafana:
	@echo "Grafana is available at: http://localhost:3000"
	@echo "Username: admin"
	@echo "Password: goliath123"

# Build and rebuild services
build:
	@echo "Building services..."
	docker compose build --no-cache

# Show resource usage
resources:
	@echo "Resource Usage:"
	docker stats --no-stream

# Backup data
backup:
	@echo "Creating backup..."
	mkdir -p backups/$(shell date +%Y%m%d_%H%M%S)
	docker exec goliath-clickhouse clickhouse-client --user goliath --password goliath123 --query "BACKUP TABLE goliath.* TO '/backup'" || echo "Backup failed - check if backup directory exists in container"
