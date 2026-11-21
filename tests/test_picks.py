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


def test_a_release_repointed_onto_an_unserved_deployment_strands_the_picks_on_it(monkeypatch):
    """Promoting a release keeps the model's name, so no pick moves; its calls still go to
    the new deployment, which must serve."""
    same = {"cheap": {"": "q", "code": "q"}, "sem": {"": "g", "code": "q"}}
    monkeypatch.setattr(picks, "picks", lambda bundles, opa="opa": same)
    before = {"q": {"provider": "KServe", "deployment": "model-prod/old"}, "g": {"provider": "VertexAI"}}
    after = {**before, "q": {"provider": "KServe", "deployment": "model-prod/new"}}
    asked = []

    def serving(d):
        asked.append(d)
        return "no replicas"

    report = picks.impact([], [], after, serving=serving, models_before=before)
    assert report["moves"] == [] and asked == ["model-prod/new"]
    assert report["stranded"] == [{"project": "cheap", "task": None, "model": "q"},
                                  {"project": "sem", "task": "code", "model": "q"}]
    assert picks.refusal(report) == ("auto would pick q for cheap, sem (code), but model-prod/new: no replicas: "
                                     "give it replicas, or set auto: false in its record")
    # the same records, not repointed: nothing to ask, nothing refused
    asked.clear()
    report = picks.impact([], [], before, serving=serving, models_before=before)
    assert asked == [] and picks.refusal(report) is None
