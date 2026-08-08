from app.evaluation import promotion_gate


def report(macro_f1: float, tp_recall: float) -> dict:
    return {
        "agents": {
            "macro_f1": macro_f1,
            "per_class": {"TruePositive": {"recall": tp_recall}},
        }
    }


def test_promotion_passes_all_three_quality_checks():
    result = promotion_gate(report(0.76, 0.72), report(0.72, 0.70), report(0.74, 0.68))
    assert result["passed"] is True
    assert all(check["passed"] for check in result["checks"].values())


def test_promotion_fails_when_delta_is_too_small():
    result = promotion_gate(report(0.74, 0.72), report(0.72, 0.70), report(0.70, 0.68))
    assert result["passed"] is False
    assert result["checks"]["macro_f1_delta"]["passed"] is False


def test_promotion_fails_below_non_llm_floor():
    result = promotion_gate(report(0.76, 0.72), report(0.70, 0.70), report(0.78, 0.68))
    assert result["passed"] is False
    assert result["checks"]["non_llm_floor"]["passed"] is False


def test_promotion_fails_when_true_positive_recall_regresses():
    result = promotion_gate(report(0.76, 0.69), report(0.70, 0.70), report(0.72, 0.68))
    assert result["passed"] is False
    assert result["checks"]["true_positive_recall"]["passed"] is False
