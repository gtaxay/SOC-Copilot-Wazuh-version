from app.services.ingest import normalize_alert

def test_normalize_wazuh_minimum():
    src = {"alert_id":"x","source":"wazuh","timestamp":"2025-08-10T00:00:00Z","rule":{"level":6}}
    a = normalize_alert(src)
    assert a.base_severity == 6 and a.source == "wazuh" and a.alert_id == "x"
