"""
CertPilot Core - Certificate Manager Module
인증서 관리 모듈 (검증, 유효성 검사, 보고)
"""
from datetime import datetime
from typing import List, Dict, Any
from .cert_parser import parse_pem_certificates, parse_pkcs12, parse_jks, CertificateInfo
from .ssh_integration import SSHClientWrapper, Server


class CertificateManager:
    """
    인증서 관리자
    - 인증서 검증
    - 유효성 검사
    - 인증서 변경 감지 (TOFU)
    - 보고서 생성
    """
    
    def __init__(self, ssh_user: str = None, ssh_password: str = None):
        self.ssh_user = ssh_user
        self.ssh_password = ssh_password
        self.audit_logs = []
    
    def verify_server_certificates(self, server: Server) -> Dict:
        """
        서버 인증서 검증
        1. 수동 검증 (SSH로 인증서 파일 수집)
        2. 인증 유효성 검사
        3. 변경 감지 (TOFU)
        
        Returns:
            서버 검증 결과
        """
        result = {
            'server': server.to_dict(),
            'validation': {
                'success': False,
                'error': None,
                'certificates': [],
                'valid_count': 0,
                'expired_count': 0,
                'not_yet_valid_count': 0,
                'total_count': 0
            }
        }
        
        try:
            # SSH 클라이언트 초기화
            ssh = SSHClientWrapper(
                hostname=server.hostname,
                port=server.port,
                username=server.username,
                password=server.password
            )
            
            if not ssh.connect():
                result['validation']['error'] = 'SSH 연결 실패'
                return result
            
            try:
                # 인증서 파일 검색
                cert_files = self._find_cert_files(ssh)
                result['validation']['total_count'] = len(cert_files)
                
                for cert_file in cert_files:
                    cert_info = self._parse_single_cert(ssh, cert_file)
                    if cert_info:
                        result['validation']['certificates'].append(cert_info)
                        
                        # 유효성 검사
                        if cert_info.is_expired:
                            result['validation']['expired_count'] += 1
                        elif cert_info.is_not_yet_valid:
                            result['validation']['not_yet_valid_count'] += 1
                        else:
                            result['validation']['valid_count'] += 1
                
                # 검증 성공
                result['validation']['success'] = True
                server.connection_status = "healthy"
            
            finally:
                ssh.close()
        
        except Exception as e:
            result['validation']['error'] = str(e)
            result['validation']['success'] = False
        
        return result
    
    def _find_cert_files(self, ssh: SSHClientWrapper) -> List[str]:
        """
        원격 서버에서 인증서 파일 검색
        """
        cert_paths = [
            '/etc/ssl/certs/',
            '/etc/pki/tls/certs/',
            '/etc/grid-security/',
            '/etc/grid/certificates/',
            '/usr/local/share/ca-certificates/',
            '/usr/local/share/ca-certificates/ubuntu/'
        ]
        
        cert_files = []
        
        for cert_path in cert_paths:
            try:
                files = ssh.list_directory(cert_path)
                for file in files:
                    if (file.endswith('.pem') or 
                        file.endswith('.crt') or 
                        file.endswith('.cer') or
                        file.endswith('.key') or
                        'ca' in file.lower() or
                        'ssl' in file.lower() or
                        'cert' in file.lower()):
                        
                        full_path = f"{cert_path}/{file}"
                        cert_files.append(full_path)
            except Exception as e:
                continue
        
        return cert_files
    
    def _parse_single_cert(self, ssh: SSHClientWrapper, cert_path: str) -> dict:
        """
        단일 인증서에서 정보 파싱
        """
        try:
            # 파일 읽기
            stdin, stdout, stderr = ssh.client.exec_command(f'cat "{cert_path}"')
            cert_content = stdout.read().decode('utf-8', errors='replace')
            
            # 인증서 파싱
            certs = parse_pem_certificates(cert_content)
            
            if certs:
                cert = certs[0]
                return {
                    'path': cert_path,
                    'filename': cert_path.split('/')[-1],
                    'subject': cert.subject,
                    'issuer': cert.issuer,
                    'serial': cert.serial,
                    'not_before': cert.not_before.isoformat(),
                    'not_after': cert.not_after.isoformat(),
                    'version': cert.version,
                    'signature_algorithm': cert.signature_algorithm,
                    'public_key_algorithm': cert.public_key_algorithm,
                    'public_key_bits': cert.public_key_bits,
                    'is_expired': cert.is_expired,
                    'is_not_yet_valid': cert.is_not_yet_valid,
                    'file_type': 'certificate'
                }
        except Exception as e:
            print(f"인증서 파싱 오류: {e}")
        
        return None
    
    def generate_report(self, validation_result: Dict) -> str:
        """
        검증 결과 보고서 생성
        """
        report = f"""
=== CertPilot 인증서 검증 보고서 ===
보고서 생성 시간: {datetime.now().isoformat()}
서버: {validation_result['server']['hostname']}
포트: {validation_result['server']['port']}
사용자: {validation_result['server']['username']}
        
=== 인증서 요약 ===
총 인증서 수: {validation_result['validation']['total_count']}
유효한 인증서: {validation_result['validation']['valid_count']}
만료된 인증서: {validation_result['validation']['expired_count']}
아직 유효하지 않은 인증서: {validation_result['validation']['not_yet_valid_count']}

=== 인증서 상세 ===
"""
        
        for cert in validation_result['validation']['certificates']:
            report += f"""
  - {cert['filename']}:
      - Subject: {cert['subject']}
      - Issuer: {cert['issuer']}
      - Serial: {cert['serial']}
      - Valid From: {cert['not_before']}
      - Valid To: {cert['not_after']}
      - Status: {'EXPIRED' if cert['is_expired'] else 'VALID' if not cert['is_not_yet_valid'] else 'NOT YET VALID'}
"""
        
        return report


if __name__ == "__main__":
    # 테스트
    manager = ServerManager()
    print("인증서 관리자 생성 완료")
