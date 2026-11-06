"""Typed Pydantic v2 schemas for Cortensor Sentinel Agent inputs and outputs."""

from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, Field


SeverityLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class VulnerabilityFinding(BaseModel):
    finding_id: str = Field(..., description="Deterministic rule identifier, e.g. SWC-107")
    title: str = Field(..., description="Concise vulnerability title")
    severity: SeverityLevel = Field(..., description="Risk severity level")
    category: str = Field(..., description="Vulnerability class or CWE/SWC category")
    evidence: str = Field(..., description="Bytecode/source pattern or RPC telemetry evidence")
    remediation: str = Field(..., description="Concrete code or configuration fix")


class CortensorRouterHealth(BaseModel):
    endpoint_url: str
    api_mode: str = Field(..., description="cortensor_completion or openai_chat")
    healthy: bool
    latency_ms: float
    active_session_ids: list[int] = Field(default_factory=list)
    precommit_timeout_seconds: int = 300
    transport_timeout_seconds: int = 420
    headroom_valid: bool = True
    offchain_urn_status: str = "ready"
    evm_block_lag: int = 0
    warnings: list[str] = Field(default_factory=list)


class LiquidityOracleRisk(BaseModel):
    pool_address: str
    token_pair: str
    top_holder_share_pct: float
    oracle_staleness_seconds: int
    twap_spot_divergence_bps: int
    timelock_hours: int
    flash_loan_manipulable: bool
    risk_notes: list[str] = Field(default_factory=list)


class RemediationPlan(BaseModel):
    target_findings: list[str]
    solidity_patches: list[str]
    cortensor_router_tuning: dict[str, str | int]
    estimated_risk_reduction_pts: int


class SentinelAuditRequest(BaseModel):
    contract_name: str
    contract_address: str
    chain_id: int = 1
    source_or_bytecode: str
    pool_address: str = "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640"
    token_pair: str = "WETH/USDC"
    cortensor_endpoint: str = "http://127.0.0.1:8080/api/v2/completions"


class ContractRiskReport(BaseModel):
    contract_address: str
    chain_id: int
    overall_risk_score: int = Field(..., ge=0, le=100)
    severity: SeverityLevel
    rpc_router_healthy: bool
    cortensor_session_id: int
    findings: list[VulnerabilityFinding]
    recommended_actions: list[str]
    summary: str
