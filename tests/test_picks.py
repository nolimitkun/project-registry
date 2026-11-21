from registry import picks


def test_moves_leave_out_task_rows_that_repeat_the_projects_own():
    before = {"cheap": {"": "q", "code": "q"}, "sem": {"": "q", "code": "d"}, "gone": {"": "q"}}
    after = {"cheap": {"": "g", "code": "g"}, "sem": {"": "g", "code": "d2"}}
    assert picks.moves(before, after) == [
        {"project": "cheap", "task": None, "before": "q", "after": "g"},
        {"project": "gone", "task": None, "before": "q", "after": None},
        {"project": "sem", "task": None, "before": "q", "after": "g"},
        {"project": "sem", "task": "code", "before": "d", "after": "d2"},
    ]


def test_refusal_names_the_model_the_projects_and_the_fix():
    report = {"moves": [{"project": "a", "task": None, "before": "q", "after": "s"},
                        {"project": "b", "task": "code", "before": "d", "after": "s"},
                        {"project": "c", "task": None, "before": "q", "after": "g"}],
              "unserved": {"s": "model-prod/s: no replicas"}, "unknown": []}
    why = picks.refusal(report)
    assert why == "auto would pick s for a, b (code), but model-prod/s: no replicas: give it replicas, or set auto: false in its record"
    assert picks.refusal({**report, "unserved": {}}) is None
