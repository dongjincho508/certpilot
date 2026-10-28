"""
CertPilot Core - SSH Integration Module
SSH 기반 원격 서버 접속 및 인증서 수집 모듈
"""
import paramiko
import os
import stat
import time
from typing import List, Dict, Any, Optional
from paramiko.client import SSHClient, AutoAddPolicy
from paramiko.sftp_client import SFTPClient


class SSHClientWrapper:
    """
    SSH 클라이언트 래퍼
    CertPilot MVP용으로 안전하게 구성된 SSH 연결
    """
    
    def __init__(
        self,
        hostname: str,
        port: int = 22,
        username: str = None,
        password: str = None,
        key_filename: str = None
    ):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.client: Optional[SSHClient] = None
        self.sftp: Optional[SFTPClient] = None
        
    def connect(self) -> bool:
        """
        SSH 연결 확립
        """
        if self.client is not None:
            return True
        
        try:
            self.client = SSHClient()
            self.client.set_missing_host_key_policy(AutoAddPolicy())
            self.client.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
            
            # 연결
            self.client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                key_filename=self.key_filename,
                timeout=10,
                auth_timeout=10,
                banner_timeout=10
            )
            
            # SFTP 세션 생성
            self.sftp = self.client.open_sftp()
            
            return True
            
        except Exception as e:
            print(f"SSH 연결 실패: {e}")
            self.close()
            return False
    
    def execute_command(self, command: str, timeout: int = 30) -> tuple:
        """
        원격 명령 실행
        반환: (stdout, stderr, return_code)
        """
        if self.client is None:
            raise Exception("SSH 연결이 없습니다. 먼저 연결하세요.")
        
        try:
            stdin, stdout, stderr = self.client.exec_command(
                command, timeout=timeout
            )
            
            # 출력 읽기
            stdout_bytes = stdout.read()
            stderr_bytes = stderr.read()
            
            # 텍스트로 변환
            stdout_text = stdout_bytes.decode('utf-8', errors='replace')
            stderr_text = stderr_bytes.decode('utf-8', errors='replace')
            
            # Return code 대기
            return_code = stdout.channel.recv_exit_status()
            
            return stdout_text, stderr_text, return_code
            
        except Exception as e:
            return "", str(e), -1
    
    def list_directory(self, remote_path: str) -> List[str]:
        """
        원격 디렉터리 목록 조회
        """
        if self.sftp is None:
            raise Exception("SFTP 세션이 없습니다.")
        
        try:
            return self.sftp.listdir(remote_path)
        except Exception as e:
            return []
    
    def stat_file(self, remote_path: str) -> dict:
        """
        원격 파일 상태 조회
        """
        if self.sftp is None:
            raise Exception("SFTP 세션이 없습니다.")
        
        try:
            remote_stat = self.sftp.stat(remote_path)
            return {
                'filename': os.path.basename(remote_path),
                'size': remote_stat.st_size,
                'mtime': remote_stat.st_mtime,
                'is_file': stat.S_ISREG(remote_stat.st_mode),
                'is_dir': stat.S_ISDIR(remote_stat.st_mode),
                'permissions': oct(remote_stat.st_mode)
            }
        except Exception as e:
            return {'error': str(e)}
    
    def download_file(self, remote_path: str, local_path: str) -> bool:
        """
        원격 파일 다운로드
        """
        if self.sftp is None:
            raise Exception("SFTP 세션이 없습니다.")
        
        try:
            self.sftp.get(remote_path, local_path)
            return True
        except Exception as e:
            print(f"파일 다운로드 실패: {e}")
            return False
    
    def close(self):
        """SSH 연결 종료"""
        if self.client:
            self.client.close()
        self.client = None
        self.sftp = None
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class Server:
    """서버 정보 데이터 클래스"""
    def __init__(
        self,
        hostname: str,
        port: int = 22,
        username: str = None,
        ip_address: str = None,
        credentials: str = "password"  # password, key, or certificate
    ):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.ip_address = ip_address
        self.credentials = credentials
        self.last_seen = None
        self.certificates = []
        self.connection_status = "unknown"
        
    def to_dict(self) -> dict:
        """서버 정보를 딕셔너리로 변환"""
        return {
            'hostname': self.hostname,
            'port': self.port,
            'username': self.username,
            'ip_address': self.ip_address,
            'credentials': self.credentials,
            'last_seen': self.last_seen,
            'connection_status': self.connection_status,
            'certificate_count': len(self.certificates) if self.certificates else 0
        }


class ServerManager:
    """
    서버 관리자
    서버 목록 관리, 인증서 수집, 검증 수행
    """
    def __init__(self, ssh_user: str = None, ssh_password: str = None):
        self.servers = []
        self.ssh_user = ssh_user
        self.ssh_password = ssh_password
    
    def add_server(self, server: Server):
        """서버 추가"""
        self.servers.append(server)
    
    def remove_server(self, hostname: str):
        """서버 제거"""
        self.servers = [s for s in self.servers if s.hostname != hostname]
    
    def get_servers(self) -> List[dict]:
        """서버 목록 반환"""
        return [s.to_dict() for s in self.servers]
    
    def collect_certificates(self, ssh_host: str, ssh_port: int = 22, 
                             ssh_user: str = None, ssh_password: str = None) -> List[dict]:
        """
        원격 서버에서 인증서 수집
        """
        # 서버 연결
        ssh = SSHClientWrapper(
            hostname=ssh_host,
            port=ssh_port,
            username=ssh_user or self.ssh_user,
            password=ssh_password or self.ssh_password
        )
        
        if not ssh.connect():
            return []
        
        try:
            # 인증서 파일 검색
            cert_files = self._find_cert_files(ssh)
            certs = []
            
            for cert_file in cert_files:
                cert_info = self._parse_cert_file(ssh, cert_file)
                if cert_info:
                    certs.append(cert_info)
            
            return certs
        
        finally:
            ssh.close()
    
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
            # 현재 디렉토리 나열
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
            from certpilot_core.cert_parser import parse_pem_text
            certs = parse_pem_text(cert_content)
            
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
