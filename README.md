<div align="center">

# 🔍 MCP-SCA-VMS

**MCP(Model Context Protocol) 기반 소프트웨어 구성 요소 분석 및 취약점 관리 자동화 시스템**

사용자가 프롬프트를 입력하면, LLM이 전체 파이프라인을 자율적으로 오케스트레이션합니다.  
**레포지토리 클론 → SBOM 생성 → 취약점 스캔 → 우선순위 분석 → 대시보드 시각화**

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![MCP](https://img.shields.io/badge/MCP-Protocol-blueviolet?style=flat-square)
![Syft](https://img.shields.io/badge/Syft-SBOM-00B4D8?style=flat-square)
![Grype](https://img.shields.io/badge/Grype-Scanner-E63946?style=flat-square)
![NVD](https://img.shields.io/badge/NVD-CVE%20DB-F4A261?style=flat-square)
![EPSS](https://img.shields.io/badge/EPSS-FIRST.org-2D6A4F?style=flat-square)
![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)
![Claude](https://img.shields.io/badge/Claude-AI-9B5DE5?style=flat-square)

</div>

---

## 시스템 아키텍처

![시스템 아키텍처](/images/architecture.png)

---

## 주요 기능

| 기능 | 설명 |
|------|------|
| **레포지토리 자동 클론** | 대상 GitHub 저장소를 비동기로 클론하고 진행 상태를 모니터링 |
| **SBOM 자동 생성** | Syft를 활용해 전체 소프트웨어 구성요소 목록(SBOM)을 CycloneDX/SPDX 형식으로 생성 |
| **취약점 데이터베이스 업데이트** | Grype의 CVE 데이터베이스를 최신 상태로 자동 갱신 |
| **SBOM 기반 취약점 스캔** | 생성된 SBOM을 Grype로 스캔하여 알려진 취약점을 탐지 |
| **CVE 상세 정보 조회** | NVD API를 통해 CVE 설명, CVSS 점수, 벡터 정보를 수집 |
| **패치 우선순위 분석** | CVSS + EPSS 백분위 기반의 복합 위험 점수로 우선순위 자동 산출 |
| **대시보드 시각화** | Streamlit 기반 인터랙티브 대시보드로 분석 결과를 직관적으로 제공 |

---

## 프로젝트 구조

```
mcp-sca-vms/
├── src/
│   ├── mcpserver/
│   │   ├── __main__.py        # MCP 서버 진입점
│   │   ├── core.py            # FastMCP 서버 초기화
│   │   ├── git_clone.py       # Git 레포지토리 클론 MCP Server
│   │   ├── syft.py            # SBOM 생성 MCP Server
│   │   ├── grype.py           # 취약점 스캔 MCP Server
│   │   ├── vuln.py            # CVE 상세 조회 및 우선순위 분석 MCP Server
│   │   └── dashboard.py       # 대시보드 데이터 전처리 MCP Server
│   └── dashboard.py           # Streamlit 대시보드 앱
├── pyproject.toml             # 프로젝트 메타데이터 및 의존성
├── requirements.txt           # Python 패키지 목록
└── README.md
```

---

## MCP Server 도구 목록

| MCP Server | 도구 | 설명 |
|-----------|------|------|
| **Git Clone MCP Server** | `start_clone` | 대상 레포지토리 비동기 클론 시작 |
| | `check_clone_status` | 클론 프로세스 상태 확인 |
| **Syft MCP Server** | `check_syft_status` | Syft 설치 여부 확인 |
| | `generate_sbom_from_repository` | SBOM 생성 (패턴 기반 제외 옵션 지원) |
| | `convert_sbom` | SBOM 포맷 변환 (CycloneDX ↔ SPDX) |
| **Grype MCP Server** | `check_grype_status` | Grype 설치 여부 확인 |
| | `check_database_status` | 취약점 DB 버전 확인 |
| | `update_database` | 취약점 DB 최신 업데이트 |
| | `scan_sbom` | SBOM 스캔 후 취약점 탐지 |
| **Vuln-manage MCP Server** | `get_vulnerability_details` | NVD API로 CVE 상세 정보 조회 |
| | `get_patch_priority_list` | CVSS + EPSS 기반 패치 우선순위 분석 |
| **Dashboard MCP Server** | `generate_dashboard` | 최종 분석 결과를 대시보드에 시각화 |

---

## 필수 소프트웨어 및 환경

- **Python** 3.13 이상
- **Syft** — [설치 안내](https://github.com/anchore/syft#installation)
- **Grype** — [설치 안내](https://github.com/anchore/grype#installation)
- **uv** — [설치 안내](https://docs.astral.sh/uv/#installation)

---

## 설치 방법

```bash
# 1. uv 설치 (최초 1회)
pip install uv

# 2. 의존성 패키지 설치
uv pip install -r requirements.txt
```

---

## 실행 방법

### MCP 서버 실행

```bash
uvx --from git+https://github.com/lhywk/mcp-sca-vms.git mcp-server
```

### Claude Desktop 연동

`claude_desktop_config.json` 파일에 아래 설정을 추가하세요.

```json
{
  "mcpServers": {
    "mcp-sca-vms": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/lhywk/mcp-sca-vms.git",
        "mcp-server"
      ]
    }
  }
}
```

### 대시보드 실행

```bash
streamlit run src/dashboard.py
```

---

## 워크플로우 및 프롬프트 예시

전체 분석은 아래 단계의 자연어 프롬프트로 자동 실행됩니다.

### Step 1 — 클론 및 SBOM 생성

```
먼저, [레포지토리 URL] 해당 레포지토리를 [디렉터리 경로] 경로에 클론하고,
Syft를 이용해 SBOM을 생성합니다.
```

**출력**: `sbom.json` (CycloneDX 형식)

---

### Step 2 — 취약점 스캔

```
다음으로, Grype의 취약점 데이터베이스를 최신 상태로 업데이트한 후,
생성된 SBOM을 스캔하여 취약점을 탐지합니다.
```

**출력**: `vulnerabilities.json` (취약점 매치 결과)

---

### Step 3 — 분석 및 시각화

```
마지막으로, 탐지된 취약점의 패치 우선순위를 분석하고
모든 최종 결과를 Streamlit 대시보드로 시각화합니다.
```

**출력**: Streamlit 대시보드 (`http://localhost:8501`)

---

## 대시보드

분석 결과는 세 가지 탭으로 구성된 인터랙티브 대시보드에서 확인할 수 있습니다.

| 탭 | 설명 |
|----|------|
| **개요 (Overview)** | 전체 취약점 수, 심각도별 분포 그래프, 패키지명/CVE ID 필터 및 상세 조회 |
| **우선순위 (Priority)** | CVSS + EPSS 기반 Risk Score로 정렬한 패치 시급 상위 10개 취약점 및 수정 버전 안내 |
| **전체 테이블 (Full Table)** | 탐지된 모든 취약점 상세 정보 및 CSV 내보내기 |

---

## 팀

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/lhywk">
        <img src="https://github.com/lhywk.png" width="100px;" alt="이호영"/>
        <br />
        <sub><b>이호영</b></sub>
      </a>
      <br />Project Manager
    </td>
    <td align="center">
      <a href="https://github.com/chon-29">
        <img src="https://github.com/chon-29.png" width="100px;" alt="손형은"/>
        <br />
        <sub><b>손형은</b></sub>
      </a>
      <br />Member
    </td>
    <td align="center">
      <a href="https://github.com/Dowonkwon">
        <img src="https://github.com/Dowonkwon.png" width="100px;" alt="권도원"/>
        <br />
        <sub><b>권도원</b></sub>
      </a>
      <br />Member
    </td>
    <td align="center">
      <a href="https://github.com/kimkiw0n">
        <img src="https://github.com/kimkiw0n.png" width="100px;" alt="김기원"/>
        <br />
        <sub><b>김기원</b></sub>
      </a>
      <br />Member
    </td>
  </tr>
</table>

---

## 참고 자료

- [Syft 공식 문서](https://anchore.github.io/syft/)
- [Grype 공식 문서](https://anchore.github.io/grype/)
- [NVD API](https://nvd.nist.gov/developers)
- [FIRST.org EPSS](https://www.first.org/epss/)
- [MCP(Model Context Protocol)](https://modelcontextprotocol.io/)

---

## 라이선스

This project is licensed under the MIT License.