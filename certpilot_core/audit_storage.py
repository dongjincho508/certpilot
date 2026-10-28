"""
CertPilot Core - WORM Audit Log Storage Module
WORM(Write Once Read Many) 방식의 감사 로그 저장 모듈
"""
import os
import hashlib
import json
import threading
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pathlib import Path


GENESIS_HASH = "0" * 64


def _entry_hash(entry: dict) -> str:
    """hash 필드를 제외한 항목 전체의 SHA-256"""
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


def _read_jsonl(path: Path) -> List[dict]:
    if not path.exists():
        return []
    with open(path, "r") as f:
        return [json.loads(line) for line in f if line.strip()]


def _verify_chain(logs: List[dict]) -> dict:
    """prev_hash 체인과 항목 해시를 검증한다 (수정·삭제·순서 변경 탐지)"""
    issues = []
    prev = GENESIS_HASH
    for i, e in enumerate(logs):
        if e.get("prev_hash") != prev:
            issues.append({"index": i, "log_id": e.get("id"), "reason": "chain_broken"})
        if e.get("hash") != _entry_hash(e):
            issues.append({"index": i, "log_id": e.get("id"), "reason": "hash_mismatch"})
        prev = e.get("hash", "")
    return {"total_logs": len(logs), "integrity_valid": not issues, "issues": issues}


class AuditLogWriter:
    """
    추가 전용(append-only) 감사 로그 라이터
    - JSON Lines 파일, 항목마다 이전 항목 해시(prev_hash)를 포함하는 SHA-256 해시 체인
    - 중간 수정·삭제·재배열은 verify_integrity() 가 탐지
    - 실제 WORM(변경 불가 저장소) 보장은 저장소 계층(파일시스템/객체 잠금)의 몫이다
    """

    def __init__(self, storage_path: str, log_type: str = "audit"):
        self.storage_path = Path(storage_path)
        self.log_type = log_type
        os.makedirs(self.storage_path, exist_ok=True)
        os.chmod(self.storage_path, 0o700)
        self.log_file = self.storage_path / f"audit_{log_type}.log"
        self.log_file.touch(exist_ok=True)
        self._lock = threading.Lock()  # 동시 기록 시 체인이 갈라지지 않도록 직렬화

    def _last_hash(self) -> str:
        last = None
        with open(self.log_file, "r") as f:
            for line in f:
                if line.strip():
                    last = line
        return json.loads(last)["hash"] if last else GENESIS_HASH

    def write(self, event_data: dict) -> dict:
        """감사 이벤트를 체인 끝에 추가한다 (스레드 안전)"""
        with self._lock:
            return self._write_locked(event_data)

    def _write_locked(self, event_data: dict) -> dict:
        event = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "log_type": self.log_type,
            "event_type": event_data.get("event_type", "unknown"),
            "description": event_data.get("description", "no description"),
            "details": event_data.get("details", {}),
            "prev_hash": self._last_hash(),
        }
        event["hash"] = _entry_hash(event)
        with open(self.log_file, "a") as f:
            f.write(json.dumps(event, sort_keys=True, default=str) + "\n")
        return {"success": True, "log_id": event["id"],
                "timestamp": event["timestamp"], "hash": event["hash"]}

    def read_logs(self, limit: int = None) -> List[dict]:
        logs = _read_jsonl(self.log_file)
        return logs[-limit:] if limit else logs

    def verify_integrity(self) -> dict:
        return _verify_chain(_read_jsonl(self.log_file))


class AuditLogReader:
    """감사 로그 리더 (읽기 전용): 디렉터리 내 모든 로그 파일"""

    def __init__(self, storage_path: str):
        self.storage_path = Path(storage_path)

    def read_all_logs(self) -> List[dict]:
        logs = []
        for log_file in sorted(self.storage_path.glob("audit_*.log")):
            logs.extend(_read_jsonl(log_file))
        return logs

    def verify_integrity(self) -> dict:
        """파일별로 체인을 검증해 결과를 합산한다"""
        total, issues = 0, []
        for log_file in sorted(self.storage_path.glob("audit_*.log")):
            r = _verify_chain(_read_jsonl(log_file))
            total += r["total_logs"]
            issues += r["issues"]
        return {"total_logs": total, "integrity_valid": not issues, "issues": issues}


if __name__ == "__main__":
    # 테스트
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # WORM 스토리지 초기화
        writer = AuditLogWriter(tmpdir, log_type="test")
        
        # 이벤트 기록
        event1 = writer.write({
            'event_type': 'cert_collection',
            'description': '인증서 수집 시작',
            'details': {'server': 'test-server-1', 'count': 3}
        })
        
        event2 = writer.write({
            'event_type': 'cert_collection',
            'description': '인증서 수집 완료',
            'details': {'server': 'test-server-1', 'count': 3, 'certs': ['cert1.pem', 'cert2.pem']}
        })
        
        print(f"기록 완료: {event1['log_id']}")
        print(f"기록 완료: {event2['log_id']}")
        
        # 로그 읽기
        reader = AuditLogReader(tmpdir)
        logs = reader.read_all_logs()
        print(f"\n총 {len(logs)}개의 로그")
        
        # 무결성 검증
        verification = reader.verify_integrity()
        print(f"무결성 검증: {verification['integrity_valid']}")
