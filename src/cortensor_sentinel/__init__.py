"""Cortensor Sentinel: DeFi Smart-Contract Risk & Cortensor Router Verifier Agent."""

from cortensor_sentinel.agent import CortensorSentinelAgent
from cortensor_sentinel.cortensor_compat import (
    apply_cortensor_adapter_fixes,
    build_sentinel_config,
)
from cortensor_sentinel.schemas import (
    ContractRiskReport,
    CortensorRouterHealth,
    LiquidityOracleRisk,
    RemediationPlan,
    SentinelAuditRequest,
    VulnerabilityFinding,
)
from cortensor_sentinel.tools import (
    audit_smart_contract_bytecode,
    generate_remediation_plan,
    inspect_liquidity_and_oracle_risk,
    verify_cortensor_rpc_health,
)

__all__ = [
    "ContractRiskReport",
    "CortensorRouterHealth",
    "CortensorSentinelAgent",
    "LiquidityOracleRisk",
    "RemediationPlan",
    "SentinelAuditRequest",
    "VulnerabilityFinding",
    "apply_cortensor_adapter_fixes",
    "audit_smart_contract_bytecode",
    "build_sentinel_config",
    "generate_remediation_plan",
    "inspect_liquidity_and_oracle_risk",
    "verify_cortensor_rpc_health",
]

__version__ = "0.1.0"
