"""
OfSec V3 — API Integration Tests
==================================
Tests for core API endpoints.
"""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_check(client: AsyncClient):
    """Test health check endpoint."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "3.0.0"


@pytest.mark.asyncio
async def test_api_status(auth_client: AsyncClient):
    """Test API v1 status endpoint."""
    response = await auth_client.get("/api/v1/status")
    assert response.status_code == 200
    data = response.json()
    assert data["api_version"] == "v1"
    assert data["status"] == "operational"
    assert "recon" in data["modules"]
    assert "scanner" in data["modules"]


@pytest.mark.asyncio
async def test_unauthenticated_recon_blocked(client: AsyncClient):
    """Test that recon endpoints require authentication."""
    response = await client.get("/api/v1/recon/results")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_recon_list_results(auth_client: AsyncClient):
    """Test listing recon results (empty initially)."""
    response = await auth_client.get("/api/v1/recon/results")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert data["total"] == 0


@pytest.mark.asyncio
async def test_scanner_list_results(auth_client: AsyncClient):
    """Test listing scanner results (empty initially)."""
    response = await auth_client.get("/api/v1/scanner/results")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert data["total"] == 0
