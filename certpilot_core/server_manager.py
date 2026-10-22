"""
CertPilot Core - Server Manager Module
원격 서버 관리 및 인증서 수집 모듈
"""
import os
import stat
from typing import List, Dict, Any, Optional
from datetime import datetime
from .ssh_integration import SSHClientWrapper, Server, ServerManager as SSHServerManager


class ServerManager:
    """
    CertPilot 서버 관리자
    - 서버 등록/관리
    - 인증서 수집
    - 실패 분류 (6가지)
    - 보고
    """
    
    def __init__(self):
        self.servers = []
        self.certificates = []
        self.failed_servers = []
        self.failed_categories = {
            'connection': 0,
            'authentication': 0,
            'timeout': 0,
            'permission': 0,
            'file_not_found': 0,
            'parse_error': 0
        }
    
    def add_server(self, server: Server):
        """서버 추가"""
        self.servers.append(server)
    
    def get_servers(self) -> List[Dict]:
        """서버 목록 반환"""
        return [s.to_dict() for s in self.servers]
    
    def collect_certificates(self, servers: List[Dict]) -> Dict:
        """
        다중 서버에서 인증서 수집
        """
        results = {
            'success': [],
            'failed': [],
            'summary': {
                'total': len(servers),
                'success': 0,
                'failed': 0
            }
        }
        
        for server_data in servers:
            server = self._create_server_from_dict(server_data)
            server_result = self._collect_from_server(server)
            
            if server_result['status'] == 'success':
                results['success'].append(server_result)
                results['summary']['success'] += 1
            else:
                results['failed'].append(server_result)
                results['summary']['failed'] += 1
                self.failed_servers.append(server_result)
        
        results['summary']['total'] = len(results['success']) + len(results['failed'])
        return results
    
    def _create_server_from_dict(self, server_data: Dict) -> Server:
        """딕셔너리에서 서버 객체 생성"""
        return Server(
            hostname=server_data['hostname'],
            port=server_data.get('port', 22),
            username=server_data.get('username'),
            ip_address=server_data.get('ip_address'),
            credentials=server_data.get('credentials')
        )
    
    def _collect_from_server(self, server: Server) -> Dict:
        """
        단일 서버에서 인증서 수집
        """
        result = {
            'hostname': server.hostname,
            'port': server.port,
            'username': server.username,
            'status': 'success',
            'certificates': [],
            'error': None
        }
        
        try:
            ssh = SSHClientWrapper(
                hostname=server.hostname,
                port=server.port,
                username=server.username,
                password=server.password
            )
            
            if not ssh.connect():
                result['status'] = 'connection_failed'
                result['error'] = 'SSH 연결 실패'
                return result
            
            # 인증서 수집
            cert_files = self._find_cert_files(ssh)
            server.certificates = []
            
            for cert_file in cert_files:
                cert_data = self._parse_cert_file(ssh, cert_file)
                if cert_data:
                    server.certificates.append(cert_data)
            
            result['certificates'] = server.certificates
            result['summary'] = {
                'total_files': len(cert_files),
                'collected': len(server.certificates)
            }
            
            ssh.close()
            
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
        
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
    
    def _parse_cert_file(self, ssh: SSHClientWrapper, cert_path: str) -> dict:
        """
        원격 인증서 파일 파싱
        """
        # 파일 존재 확인
        file_info = ssh.stat_file(cert_path)
        if file_info.get('error'):
            return None
        
        # 파일 읽기
        stdin, stdout, stderr = ssh.client.exec_command(f'cat "{cert_path}"')
        cert_content = stdout.read().decode('utf-8', errors='replace')
        
        # 인증서 정보 파싱
        try:
            from certpilot_core.cert_parser import parse_pem_certificates
            certs = parse_pem_certificates(cert_content)
            
            if certs:
                return {
                    'path': cert_path,
                    'filename': cert_path.split('/')[-1],
                    'certs': [c.__dict__ for c in certs],
                    'file_size': file_info['size'],
                    'modified_time': file_info['mtime'],
                    'file_type': 'certificate'
                }
        except Exception as e:
            print(f"인증서 파싱 오류: {e}")
        
        return None


if __name__ == "__main__":
    # 테스트
    import tempfile
    
    # 테스트 서버 생성
    manager = ServerManager()
    manager.add_server(Server(
        hostname='test-server',
        port=22,
        username='test',
        credentials='password'
    ))
    
    # 테스트
    print("서버 관리자 생성 완료")
    print(f"서버 수: {len(manager.servers)}")
