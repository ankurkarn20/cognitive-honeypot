"""Anomaly detection with an Isolation Forest (Liu, Ting and Zhou, 2008).

An Isolation Forest isolates points with random splits; anomalies, being few and
different, are isolated in fewer splits, so a short average path means "anomalous". No
attack labels are needed, which suits a honeypot that sees attacks nobody has labelled.
Features are log-scaled (counts are heavy-tailed) and standardised. `contamination`, the
share of sessions flagged, was set to 0.1 on simulated traffic.
"""
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


@dataclass
class Detector:
    features: list[str]
    scaler: StandardScaler
    forest: IsolationForest

    @classmethod
    def fit(cls, sessions: pd.DataFrame, features: list[str], contamination: float = 0.1,
            seed: int = 42) -> "Detector":
        x = np.log1p(sessions[features].astype(float).to_numpy())
        scaler = StandardScaler().fit(x)
        forest = IsolationForest(n_estimators=300, contamination=contamination,
                                 random_state=seed).fit(scaler.transform(x))
        return cls(features, scaler, forest)

    def score(self, sessions: pd.DataFrame) -> pd.DataFrame:
        """The sessions with an anomaly score (higher = more anomalous) and a flag."""
        out = sessions.copy()
        if out.empty:
            return out.assign(score=[], anomalous=[])
        x = self.scaler.transform(np.log1p(sessions[self.features].astype(float).to_numpy()))
        decision = self.forest.decision_function(x)
        out["score"] = np.round(-decision, 4)
        out["anomalous"] = decision < 0
        return out.sort_values("score", ascending=False)

