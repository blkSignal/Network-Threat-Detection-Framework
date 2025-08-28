#!/usr/bin/env python3
"""
Goliath Systems API Server

Provides REST API endpoints for:
- Threat detection
- System monitoring
- Configuration management
- Alert management
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional
import uvicorn
import logging
import yaml
import os
from datetime import datetime, timedelta

# Import our detection modules
import sys
sys.path.append('../detectors/python')
from dga_detector import DGADetector
from beacon_detector import BeaconDetector
from ml_enhancer import MLThreatDetector
from performance_optimizer import PerformanceOptimizer

# Initialize FastAPI app
app = FastAPI(
    title="Goliath Systems API",
    description="Network Threat Detection Pipeline API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Initialize components
dga_detector = DGADetector()
beacon_detector = BeaconDetector()
ml_detector = MLThreatDetector()
perf_optimizer = PerformanceOptimizer()

# Data models
class ThreatRequest(BaseModel):
    data: str
    type: str  # "dga" or "beacon"
    threshold: Optional[float] = 0.6

class ThreatResponse(BaseModel):
    threat_detected: bool
    score: float
    classification: str
    details: Dict
    timestamp: datetime

class SystemStatus(BaseModel):
    status: str
    uptime: str
    memory_usage: float
    cpu_usage: float
    active_detections: int

class AlertConfig(BaseModel):
    email_enabled: bool
    slack_enabled: bool
    threshold: float

# Authentication dependency
async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    # Simple token verification - in production, use proper JWT validation
    if credentials.credentials != "goliath-secure-token":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token"
        )
    return credentials.credentials

# Health check endpoint
@app.get("/health", response_model=SystemStatus)
async def health_check():
    """Get system health status."""
    try:
        metrics = perf_optimizer.get_system_metrics()
        return SystemStatus(
            status="healthy",
            uptime="24h",  # Placeholder
            memory_usage=metrics['memory_percent'],
            cpu_usage=metrics['cpu_percent'],
            active_detections=0  # Placeholder
        )
    except Exception as e:
        logging.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail="Health check failed")

# DGA Detection endpoint
@app.post("/detect/dga", response_model=ThreatResponse)
async def detect_dga(request: ThreatRequest, token: str = Depends(verify_token)):
    """Detect DGA domains."""
    try:
        # Create temporary file for processing
        temp_file = f"/tmp/dga_temp_{datetime.now().timestamp()}.log"
        with open(temp_file, 'w') as f:
            f.write(f"1704067200.000000\tabc123\t192.168.1.100\t12345\t8.8.8.8\t53\tudp\t12345\t0.001\t{request.data}\t1\tC_INTERNET\t1\tA\t0\tNOERROR\tF\tF\tT\tT\t0\t-\t-\tF")
        
        # Process with DGA detector
        results = dga_detector.process_zeek_log(temp_file)
        
        # Clean up
        os.remove(temp_file)
        
        if results:
            result = results[0]
            return ThreatResponse(
                threat_detected=result['score'] >= request.threshold,
                score=result['score'],
                classification=result['classification'],
                details=result['scores'],
                timestamp=datetime.now()
            )
        else:
            return ThreatResponse(
                threat_detected=False,
                score=0.0,
                classification="clean",
                details={},
                timestamp=datetime.now()
            )
            
    except Exception as e:
        logging.error(f"DGA detection failed: {e}")
        raise HTTPException(status_code=500, detail=f"DGA detection failed: {str(e)}")

# Beacon Detection endpoint
@app.post("/detect/beacon", response_model=ThreatResponse)
async def detect_beacon(request: ThreatRequest, token: str = Depends(verify_token)):
    """Detect beaconing behavior."""
    try:
        # Create temporary file for processing
        temp_file = f"/tmp/beacon_temp_{datetime.now().timestamp()}.log"
        with open(temp_file, 'w') as f:
            f.write(f"1704067200.000000\tabc123\t192.168.1.100\t12345\t10.0.0.1\t80\ttcp\thttp\t1.5\t100\t200\tSF\tT\tF\t0\tShADad\t5\t540\t4\t480\t-")
        
        # Process with beacon detector
        results = beacon_detector.process_zeek_log(temp_file)
        
        # Clean up
        os.remove(temp_file)
        
        if results:
            result = results[0]
            return ThreatResponse(
                threat_detected=result['score'] >= request.threshold,
                score=result['score'],
                classification=result['classification'],
                details=result['metrics'],
                timestamp=datetime.now()
            )
        else:
            return ThreatResponse(
                threat_detected=False,
                score=0.0,
                classification="clean",
                details={},
                timestamp=datetime.now()
            )
            
    except Exception as e:
        logging.error(f"Beacon detection failed: {e}")
        raise HTTPException(status_code=500, detail=f"Beacon detection failed: {str(e)}")

# ML Enhancement endpoint
@app.post("/ml/enhance")
async def ml_enhance(data: List[Dict], token: str = Depends(verify_token)):
    """Enhance detection with machine learning."""
    try:
        # Train models if not already trained
        if not ml_detector.is_trained:
            ml_detector.train_anomaly_detector(data)
        
        # Detect anomalies
        anomalies = ml_detector.detect_anomalies(data)
        
        return {
            "anomalies_detected": sum(anomalies),
            "total_samples": len(data),
            "anomaly_rate": sum(anomalies) / len(data),
            "enhanced_results": [
                {
                    "index": i,
                    "is_anomaly": anomaly,
                    "original_data": item
                }
                for i, (anomaly, item) in enumerate(zip(anomalies, data))
            ]
        }
        
    except Exception as e:
        logging.error(f"ML enhancement failed: {e}")
        raise HTTPException(status_code=500, detail=f"ML enhancement failed: {str(e)}")

# Performance optimization endpoint
@app.post("/performance/optimize")
async def optimize_performance(token: str = Depends(verify_token)):
    """Optimize system performance."""
    try:
        # Get current metrics
        metrics = perf_optimizer.get_system_metrics()
        
        # Optimize memory
        memory_opt = perf_optimizer.optimize_memory_usage()
        
        # Get recommendations
        recommendations = perf_optimizer.get_optimization_recommendations()
        
        return {
            "current_metrics": metrics,
            "memory_optimization": memory_opt,
            "recommendations": recommendations,
            "optimization_timestamp": datetime.now()
        }
        
    except Exception as e:
        logging.error(f"Performance optimization failed: {e}")
        raise HTTPException(status_code=500, detail=f"Performance optimization failed: {str(e)}")

# Configuration management endpoint
@app.get("/config")
async def get_config(token: str = Depends(verify_token)):
    """Get current configuration."""
    try:
        config_path = "../config/config.yaml"
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        logging.error(f"Config retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Config retrieval failed: {str(e)}")

# Statistics endpoint
@app.get("/stats")
async def get_stats(token: str = Depends(verify_token)):
    """Get system statistics."""
    try:
        return {
            "total_detections": 0,  # Placeholder
            "threats_blocked": 0,    # Placeholder
            "false_positives": 0,    # Placeholder
            "system_uptime": "24h",  # Placeholder
            "last_scan": datetime.now(),
            "active_monitors": 4,    # DGA, Beacon, ML, Performance
            "api_requests": 0        # Placeholder
        }
    except Exception as e:
        logging.error(f"Stats retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Stats retrieval failed: {str(e)}")

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    # Run the server
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
