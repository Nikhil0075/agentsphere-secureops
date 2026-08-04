"""Non-LLM baseline classifier.

This model exists to be *compared against*, not to win. Two things depend on it:

* **Honest evaluation.** "Our agents reach macro F1 X" means nothing without a cheap gradient
  boosting model on the same features and the same split saying what X is worth. §12.3 lists "is
  this just an LLM wrapper?" as an expected question, and a measured baseline is the answer that
  does not require the judge to take anything on trust.
* **A calibrated prior for Triage.** The Triage agent receives the baseline's probability
  alongside the evidence, so its rationale can agree or disagree with a number rather than only
  with prose.

LightGBM is the primary implementation; sklearn's ``HistGradientBoostingClassifier`` is a drop-in
fallback so the pipeline never depends on a wheel being available on the host.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from app.data.schema import (
    CATEGORICAL_FEATURES,
    INT_TO_LABEL,
    LABEL_TO_INT,
    LABELS,
    NUMERIC_FEATURES,
)

try:  # pragma: no cover - environment dependent
    import lightgbm as lgb

    HAS_LIGHTGBM = True
except ImportError:  # pragma: no cover
    lgb = None
    HAS_LIGHTGBM = False

_UNSEEN = -1


@dataclass
class BaselineModel:
    """Gradient-boosted trees over incident-level features."""

    model: Any = None
    categories: dict[str, list[str]] | None = None
    implementation: str = ""

    # --- feature preparation ------------------------------------------------------------

    def _encode(self, frame: pd.DataFrame, fit: bool = False) -> pd.DataFrame:
        """Ordinal-encode categoricals against a mapping learned on the training split.

        Values unseen at training time map to ``-1`` rather than to an arbitrary existing
        category. A new detector id appearing in production must not be silently treated as some
        other detector.
        """
        out = pd.DataFrame(index=frame.index)

        for column in NUMERIC_FEATURES:
            out[column] = pd.to_numeric(frame.get(column, 0), errors="coerce").fillna(0.0)

        if fit:
            self.categories = {}
        for column in CATEGORICAL_FEATURES:
            values = frame.get(column, pd.Series("", index=frame.index)).astype(str).fillna("")
            if fit:
                self.categories[column] = sorted(values.unique())
            lookup = {v: i for i, v in enumerate(self.categories.get(column, []))}
            out[column] = values.map(lookup).fillna(_UNSEEN).astype(int)

        return out

    # --- training -----------------------------------------------------------------------

    def fit(self, train: pd.DataFrame, seed: int = 20260805) -> "BaselineModel":
        features = self._encode(train, fit=True)
        target = train["label"].map(LABEL_TO_INT).astype(int)

        # The class distribution is skewed (BenignPositive dominates GUIDE). Without balancing,
        # the model learns to answer "benign" and posts a respectable accuracy while being
        # useless at the class that matters — a missed true positive is the dangerous failure.
        counts = target.value_counts()
        weights = target.map({k: len(target) / (len(counts) * v) for k, v in counts.items()})

        if HAS_LIGHTGBM:
            self.implementation = f"lightgbm-{lgb.__version__}"
            self.model = lgb.LGBMClassifier(
                objective="multiclass",
                num_class=len(LABELS),
                n_estimators=300,
                learning_rate=0.05,
                num_leaves=31,
                min_child_samples=20,
                subsample=0.9,
                subsample_freq=1,
                colsample_bytree=0.9,
                random_state=seed,
                n_jobs=-1,
                verbose=-1,
            )
            self.model.fit(
                features,
                target,
                sample_weight=weights,
                categorical_feature=list(CATEGORICAL_FEATURES),
            )
        else:  # pragma: no cover - only on hosts without a LightGBM wheel
            from sklearn.ensemble import HistGradientBoostingClassifier
            import sklearn

            self.implementation = f"sklearn-hgb-{sklearn.__version__}"
            self.model = HistGradientBoostingClassifier(
                max_iter=300,
                learning_rate=0.05,
                categorical_features=[
                    features.columns.get_loc(c) for c in CATEGORICAL_FEATURES
                ],
                random_state=seed,
            )
            self.model.fit(features, target, sample_weight=weights)

        return self

    # --- inference ----------------------------------------------------------------------

    def predict_proba(self, frame: pd.DataFrame) -> np.ndarray:
        return self.model.predict_proba(self._encode(frame))

    def predict(self, frame: pd.DataFrame) -> list[str]:
        return [INT_TO_LABEL[int(i)] for i in self.predict_proba(frame).argmax(axis=1)]

    def predict_one(self, incident: dict | pd.Series) -> dict[str, Any]:
        """Prediction for a single incident, in the shape ``BaselinePrediction`` expects."""
        if isinstance(incident, pd.Series):
            incident = incident.to_dict()
        proba = self.predict_proba(pd.DataFrame([incident]))[0]
        index = int(proba.argmax())
        return {
            "label": INT_TO_LABEL[index],
            "confidence": float(proba[index]),
            "probabilities": {INT_TO_LABEL[i]: float(p) for i, p in enumerate(proba)},
            "model_name": self.implementation,
        }

    def true_positive_probability(self, incident: dict | pd.Series) -> float:
        """P(TruePositive) — the signal the risk score consumes."""
        return self.predict_one(incident)["probabilities"]["TruePositive"]

    def feature_importance(self) -> dict[str, float]:
        names = list(NUMERIC_FEATURES) + list(CATEGORICAL_FEATURES)
        raw = getattr(self.model, "feature_importances_", None)
        if raw is None:
            return {}
        total = float(sum(raw)) or 1.0
        return {
            name: round(float(value) / total, 4)
            for name, value in sorted(zip(names, raw), key=lambda kv: -kv[1])
        }

    # --- persistence --------------------------------------------------------------------

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "categories": self.categories,
                "implementation": self.implementation,
            },
            path,
        )
        return path

    @classmethod
    def load(cls, path: str | Path) -> "BaselineModel":
        payload = joblib.load(Path(path))
        return cls(
            model=payload["model"],
            categories=payload["categories"],
            implementation=payload["implementation"],
        )


def load_default(path: str | Path) -> BaselineModel | None:
    """Load the trained baseline, or ``None`` if it has not been trained yet.

    Callers degrade rather than crash: the workflow still runs without a baseline, it just loses
    the comparison point and says so.
    """
    path = Path(path)
    if not path.exists():
        return None
    try:
        return BaselineModel.load(path)
    except Exception:  # noqa: BLE001 - a stale pickle must not take the demo down
        return None


def metrics_summary(path: str | Path) -> dict:
    path = Path(path)
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
