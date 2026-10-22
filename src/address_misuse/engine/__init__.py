"""Module 2: engine chấm điểm rủi ro R(A, C) — đặc tả ở docs/RISK_SCORE.md."""

from address_misuse.engine.features import Features, FeatureStore
from address_misuse.engine.score import DEFAULT_WEIGHTS, RiskResult, TxContext, score, score_features

__all__ = ["DEFAULT_WEIGHTS", "Features", "FeatureStore", "RiskResult", "TxContext", "score", "score_features"]
