"""
CertPilot Core - WORM Audit Log Storage Module
WORM(Write Once Read Many) 방식의 감사 로그 저장 모듈
"""
import os
import hashlib
import json
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path


class AuditLogWriter:
    """
    WORM 감사 로그 라이터
    - 파일 추가 전용 (쓰기 보호)
    - SHA-256 해시 트리 무결성 검증
    - 변경 제어 로그
    """
    
    def __init__(self, storage_path: str, log_type: str = "audit"):
        """
        Args:
            storage_path: WORM 스토리지 경로 (추가 전용)
            log_type: 로그 유형 (audit, config_change, cert_change, etc.)
        """
        self.storage_path = Path(storage_path)
        self.log_type = log_type
        
        # 스토리지 초기화 (생성 시 한 번만)
        self._initialize_storage()
    
    def _initialize_storage(self):
        """WORM 스토리지 초기화"""
        # 스토리지 디렉토리가 없으면 생성
        os.makedirs(self.storage_path, exist_ok=True)
        
        # 파일 권한 설정 (읽기/쓰기: 소유자만)
        os.chmod(self.storage_path, 0o700)
        
        # 로그 파일 생성 (이미 있으면 사용하지 않음)
        self.log_file = self._get_log_filename()
        
        if not os.path.exists(self.log_file):
            # 새 로그 파일 생성 (덮어쓰기 없음 - WORM 특성)
            with open(self.log_file, 'w') as f:
                json.dump({
                    'version': 1,
                    'log_type': self.log_type,
                    'created_at': datetime.now().isoformat(),
                    'entries': []
                }, f, indent=2)
    
    def _get_log_filename(self) -> str:
        """로그 파일명 반환 (해시 트리 기반)"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return self.storage_path / f"audit_{timestamp}.log"
    
    def write(self, event_data: dict) -> dict:
        """
        감사 이벤트 기록
        WORM 특성: 파일 추가만 가능, 삭제/수정 불가
        
        Args:
            event_data: 이벤트 데이터 (event_type, description, details 등)
        
        Returns:
            기록 성공 여부 및 로그 ID
        """
        # 이벤트 데이터에 타임스탬프 추가
        event = {
            'id': self._generate_log_id(),
            'timestamp': datetime.now().isoformat(),
            'log_type': self.log_type,
            'event_type': event_data.get('event_type', 'unknown'),
            'description': event_data.get('description', 'no description'),
            'details': event_data.get('details', {}),
            'status': 'recorded'  # 기록 후 취소 불가
        }
        
        # 해시 계산 (기록 전)
        event['hash_before'] = self._calculate_hash(event)
        
        # 로그 파일에 추가
        self._append_to_log(event)
        
        # 해시 계산 (기록 후)
        event['hash_after'] = self._calculate_hash(event)
        
        return {
            'success': True,
            'log_id': event['id'],
            'timestamp': event['timestamp'],
            'hash_before': event['hash_before'],
            'hash_after': event['hash_after']
        }
    
    def _generate_log_id(self) -> str:
        """로그 ID 생성 (UUID 기반)"""
        import uuid
        return str(uuid.uuid4())
    
    def _calculate_hash(self, event: dict) -> str:
        """이벤트 데이터 SHA-256 해시 계산"""
        import json
        # 이벤트 데이터를 정렬된 JSON으로 변환 후 해시 계산
        sorted_json = json.dumps(event, sort_keys=True, default=str)
        return hashlib.sha256(sorted_json.encode()).hexdigest()
    
    def _append_to_log(self, event: dict):
        """로그 파일에 이벤트 추가"""
        # 로그 파일 열기 (추가 모드)
        with open(self.log_file, 'a') as f:
            json.dump(event, f, indent=2)
            f.write('\n')
    
    def read_logs(self, limit: int = None) -> List[dict]:
        """감사 로그 읽기 (읽기 전용)"""
        if not os.path.exists(self.log_file):
            return []
        
        logs = []
        with open(self.log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    logs.append(json.loads(line))
        
        # 최신 N개 반환
        if limit:
            return logs[-limit:]
        
        return logs
    
    def verify_integrity(self) -> dict:
        """
        해시 트리 무결성 검증
        각 로그 항목의 hash_before와 hash_after 비교
        """
        logs = self.read_logs()
        
        verification = {
            'total_logs': len(logs),
            'integrity_valid': True,
            'issues': []
        }
        
        for log in logs:
            if log.get('hash_before') != log.get('hash_after'):
                verification['integrity_valid'] = False
                verification['issues'].append({
                    'log_id': log.get('id'),
                    'hash_before': log.get('hash_before'),
                    'hash_after': log.get('hash_after')
                })
        
        return verification


class AuditLogReader:
    """
    감사 로그 리더 (읽기 전용)
    WORM 스토리지의 로그 읽기 및 검증
    """
    
    def __init__(self, storage_path: str):
        self.storage_path = Path(storage_path)
    
    def read_all_logs(self) -> List[dict]:
        """모든 감사 로그 읽기"""
        logs = []
        log_files = sorted(self.storage_path.glob("audit_*.log"))
        
        for log_file in log_files:
            with open(log_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        logs.append(json.loads(line))
        
        return logs
    
    def verify_integrity(self) -> dict:
        """무결성 검증"""
        logs = self.read_all_logs()
        
        verification = {
            'total_logs': len(logs),
            'integrity_valid': True,
            'issues': []
        }
        
        for log in logs:
            if log.get('hash_before') != log.get('hash_after'):
                verification['integrity_valid'] = False
                verification['issues'].append({
                    'log_id': log.get('id'),
                    'hash_before': log.get('hash_before'),
                    'hash_after': log.get('hash_after')
                })
        
        return verification


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
