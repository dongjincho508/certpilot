# [초안·미검증] IIS 서버에서 실행: 발급 서버가 만든 PFX 를 가져와 HTTPS 바인딩의 인증서를 교체한다.
# 실행 전 발급 서버에서:  openssl pkcs12 -export -inkey privkey.pem -in fullchain.pem -out site.pfx -passout pass:<임시암호>
# 사용 예:  .\deploy-iis.ps1 -PfxPath C:\certs\site.pfx -PfxPassword (Read-Host -AsSecureString) -SiteName "Default Web Site"
param(
  [Parameter(Mandatory)] [string] $PfxPath,
  [Parameter(Mandatory)] [securestring] $PfxPassword,
  [Parameter(Mandatory)] [string] $SiteName,
  [int] $Port = 443
)
$ErrorActionPreference = "Stop"
Import-Module WebAdministration
$cert = Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation Cert:\LocalMachine\My -Password $PfxPassword
$binding = Get-WebBinding -Name $SiteName -Protocol https -Port $Port
if (-not $binding) { throw "$SiteName 의 https:$Port 바인딩이 없습니다." }
$binding.AddSslCertificate($cert.Thumbprint, "My")
Write-Output "교체 완료: $($cert.Subject) / 만료 $($cert.NotAfter) / 지문 $($cert.Thumbprint)"
# 이전 인증서 정리는 새 인증서 정상 확인 후 수동으로 수행하세요.
