/**
 * CertPilot MVP - 관리 대시보드 프론트엔드
 * REST API 연동 및 UI 로직
 */

// API BASE URL
const API_BASE_URL = 'http://localhost:8080';

// DOM Elements
const certificatesBody = document.getElementById('certificates-body');
const serversBody = document.getElementById('servers-body');
const auditLogsBody = document.getElementById('audit-logs-body');
const lastUpdate = document.getElementById('last-update');

/**
 * API 호출 헬퍼
 */
async function apiCall(endpoint, options = {}) {
    const url = `${API_BASE_URL}${endpoint}`;
    const config = {
        headers: {
            'Content-Type': 'application/json',
            ...options.headers
        },
        ...options
    };

    try {
        const response = await fetch(url, config);
        if (response.status === 204) {
            return null;
        }
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || '요청 처리 중 오류가 발생했습니다.');
        }
        return data;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

/**
 * 서버 목록 조회
 */
async function fetchServers() {
    try {
        const data = await apiCall('/servers');
        const tbody = serversBody;
        tbody.innerHTML = '';

        if (data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center">서버 데이터가 없습니다.</td></tr>';
            return;
        }

        data.forEach(server => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${escapeHtml(server.hostname)}</td>
                <td>${escapeHtml(server.ip_address)}</td>
                <td>${escapeHtml(server.os_type)}</td>
                <td>${server.ssh_port}</td>
                <td>
                    <span class="badge badge-${getStatusClass(server.status)}">${server.status}</span>
                </td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" onclick="refreshServerCertificates(${server.id})">
                        <i class="fas fa-sync-alt"></i>
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
    } catch (error) {
        console.error('Error fetching servers:', error);
        serversBody.innerHTML = '<tr><td colspan="6" class="text-center text-danger">서버 목록을 불러오는데 실패했습니다.</td></tr>';
    }
}

/**
 * 인증서 목록 조회
 */
async function refreshCertificates() {
    const lastUpdateEl = document.getElementById('last-update');
    lastUpdateEl.textContent = '로딩 중...';

    try {
        const data = await apiCall('/certificates');
        const tbody = certificatesBody;
        tbody.innerHTML = '';

        if (data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center">인증서 데이터가 없습니다.</td></tr>';
            lastUpdateEl.textContent = '마지막 업데이트: 방금';
            return;
        }

        data.forEach(cert => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>
                    <i class="fas fa-server text-muted me-1"></i>${escapeHtml(cert.server_hostname)}
                </td>
                <td>${escapeHtml(cert.server_ip)}</td>
                <td>${escapeHtml(cert.common_name)}</td>
                <td>${escapeHtml(cert.issuer)}</td>
                <td>${formatISODate(cert.not_before)}</td>
                <td>
                    ${getExpiryBadge(cert.expiry_days)}
                </td>
                <td>${getStatusBadge(cert.status)}</td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" onclick="viewCertificateDetail(${cert.id})">
                        <i class="fas fa-eye"></i>
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });

        lastUpdateEl.textContent = `마지막 업데이트: ${new Date().toISOString()}`;
    } catch (error) {
        console.error('Error fetching certificates:', error);
        certificatesBody.innerHTML = '<tr><td colspan="8" class="text-center text-danger">인증서 목록을 불러오는데 실패했습니다.</td></tr>';
        lastUpdateEl.textContent = '마지막 업데이트: 오류 발생';
    }
}

/**
 * 인증서 상세 정보 조회
 */
async function viewCertificateDetail(certId) {
    try {
        const data = await apiCall(`/certificates/${certId}`);
        // TODO: 상세 뷰로 이동
        console.log('Certificate detail:', data);
        alert('상세 정보: ' + JSON.stringify(data, null, 2));
    } catch (error) {
        console.error('Error fetching certificate detail:', error);
        alert('인증서 상세 정보를 불러오는데 실패했습니다.');
    }
}

/**
 * 서버 인증서로 확인
 */
async function verifyServer(servers) {
    const selectedServers = document.querySelectorAll('input[name="server_check"]:checked');
    const serverIds = Array.from(selectedServers).map(el => parseInt(el.value));

    if (serverIds.length === 0) {
        alert('확인할 서버를 선택해주세요.');
        return;
    }

    try {
        const data = await apiCall('/servers/verify', {
            method: 'POST',
            body: JSON.stringify({ server_ids: serverIds })
        });
        alert('검증 완료:\n' + JSON.stringify(data, null, 2));
    } catch (error) {
        console.error('Error verifying servers:', error);
        alert('검증 중 오류가 발생했습니다.');
    }
}

/**
 * 서버 등록
 */
async function registerServer(e) {
    e.preventDefault();

    const formData = {
        hostname: document.getElementById('server-name').value,
        ip_address: document.getElementById('server-hostname').value,
        ssh_port: parseInt(document.getElementById('server-ssh-port').value),
        ssh_username: document.getElementById('server-ssh-user').value,
        ssh_key_path: document.getElementById('server-ssh-key').value,
        os_type: document.getElementById('server-os').value,
        os_version: document.getElementById('server-os-version').value,
        status: 'active'
    };

    try {
        await apiCall('/servers', {
            method: 'POST',
            body: JSON.stringify(formData)
        });
        alert('서버가 성공적으로 등록되었습니다.');
        resetForm();
        fetchServers();
        refreshCertificates();
    } catch (error) {
        console.error('Error registering server:', error);
        alert('서버 등록에 실패했습니다: ' + error.message);
    }
}

/**
 * 서버 삭제 (실행 취소)
 */
function resetForm() {
    document.getElementById('server-form').reset();
}

/**
 * 만료까지 일수 배지
 */
function getExpiryBadge(days) {
    if (days > 30) {
        return '<span class="badge badge-valid">유효</span>';
    } else if (days > 0) {
        return '<span class="badge badge-warning">만료 임박 (' + days + '일)</span>';
    } else if (days === 0) {
        return '<span class="badge badge-danger">만료</span>';
    } else {
        return '<span class="badge badge-expired">-(' + Math.abs(days) + '일)</span>';
    }
}

/**
 * 상태 배지
 */
function getStatusBadge(status) {
    const badges = {
        valid: '<span class="badge badge-valid">정상</span>',
        expiring_soon: '<span class="badge badge-warning">만료 임박</span>',
        expired: '<span class="badge badge-expired">만료</span>',
        corrupt: '<span class="badge badge-danger">손상</span>',
        missing: '<span class="badge badge-other">누락</span>',
        unknown: '<span class="badge badge-unknown">알 수 없음</span>'
    };
    return badges[status] || badges.unknown;
}

function getStatusClass(status) {
    const badges = {
        valid: 'valid',
        expiring_soon: 'expiring-soon',
        expired: 'expired',
        corrupt: 'corrupt',
        missing: 'missing',
        unknown: 'unknown'
    };
    return badges[status] || 'unknown';
}

/**
 * 날짜 포맷 (ISO 8601)
 */
function formatISODate(dateStr) {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    return date.toISOString().split('T')[0];
}

/**
 * HTML 이스케이프
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * 페이지 로드 시 데이터 초기화
 */
document.addEventListener('DOMContentLoaded', () => {
    fetchServers();
    refreshCertificates();

    // 서버 등록 폼 제출
    document.getElementById('server-form').addEventListener('submit', registerServer);
});

// 환형 로딩 스피너 표시
function showLoading() {
    const updateEl = document.getElementById('last-update');
    updateEl.innerHTML = '<span class="spinner-border spinner-border-sm"></span> 로딩 중...';
}
