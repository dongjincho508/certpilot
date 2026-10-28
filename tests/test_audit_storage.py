from certpilot_core.audit_storage import AuditLogWriter


def test_write_returns_log_id(tmp_path):
    w = AuditLogWriter(str(tmp_path))
    r = w.write({"event_type": "scan", "description": "x"})
    assert r["success"] and r["log_id"]


def test_written_events_can_be_read_back(tmp_path):
    w = AuditLogWriter(str(tmp_path))
    w.write({"event_type": "scan"})
    w.write({"event_type": "scan2"})
    assert [e["event_type"] for e in w.read_logs()] == ["scan", "scan2"]


def test_integrity_valid_for_untouched_log(tmp_path):
    w = AuditLogWriter(str(tmp_path))
    w.write({"event_type": "scan"})
    assert w.verify_integrity()["integrity_valid"]


def test_integrity_detects_tampering(tmp_path):
    w = AuditLogWriter(str(tmp_path))
    w.write({"event_type": "scan"})
    text = open(w.log_file).read().replace('"scan"', '"hacked"')
    open(w.log_file, "w").write(text)
    assert not w.verify_integrity()["integrity_valid"]


def test_integrity_detects_deleted_entry(tmp_path):
    w = AuditLogWriter(str(tmp_path))
    for i in range(3):
        w.write({"event_type": f"e{i}"})
    lines = open(w.log_file).read().splitlines()
    open(w.log_file, "w").write("\n".join([lines[0], lines[2]]) + "\n")
    assert not w.verify_integrity()["integrity_valid"]


def test_chain_continues_after_restart(tmp_path):
    AuditLogWriter(str(tmp_path)).write({"event_type": "a"})
    w2 = AuditLogWriter(str(tmp_path))
    w2.write({"event_type": "b"})
    assert len(w2.read_logs()) == 2 and w2.verify_integrity()["integrity_valid"]


def test_reader_aggregates(tmp_path):
    from certpilot_core.audit_storage import AuditLogReader
    AuditLogWriter(str(tmp_path), "x").write({"event_type": "a"})
    AuditLogWriter(str(tmp_path), "y").write({"event_type": "b"})
    r = AuditLogReader(str(tmp_path))
    assert len(r.read_all_logs()) == 2 and r.verify_integrity()["integrity_valid"]
