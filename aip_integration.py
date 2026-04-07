#!/usr/bin/env python3
"""
AIP Integration Module
Adds AIP routes to the main API server
"""

# This file is imported by api-server-v2.py to add AIP routes

import sys
import os

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from aip_api import aip_router, credentials_viewer_router
    
    def add_aip_routes(app):
        """Add AIP routes to FastAPI app"""
        app.include_router(aip_router)
        app.include_router(credentials_viewer_router)
        print("✓ AIP v0.3.1 routes registered")
        return app
        
except ImportError as e:
    print(f"Warning: Could not import AIP modules: {e}")
    print("AIP routes will not be available")
    
    def add_aip_routes(app):
        """No-op when AIP modules not available"""
        return app
