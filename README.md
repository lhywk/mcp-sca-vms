# MCP-SCA-VMS 시스템 사용 안내

### 1. 프로젝트 개요
- 이 프로젝트는 소프트웨어 구성 분석(SCA) 및 취약점 관리 자동화를 위한 MCP 기반 시스템입니다.

### 2. 필수 소프트웨어 및 환경
- Python 3.10 이상
- Syft, Grype 등 외부 CLI 도구
    - [Syft 설치 안내](https://github.com/anchore/syft#installation)
    - [Grype 설치 안내](https://github.com/anchore/grype#installation)

### 3. 의존성 설치 (uv 권장)
1. uv 설치 (최초 1회만)
    ```bash
    pip install uv
    ```
2. 패키지 설치
    ```bash
    uv pip install -r requirements.txt
    ```
3. (가상환경 사용 시) 가상환경을 먼저 활성화한 뒤 위 명령어를 실행하세요.

### 4. 주요 실행 방법
- 각 MCP 서버 실행:
    - 취약점 관리 서버: `python src/vuln_manage_mcp_server.py`
    - SBOM 생성 서버: `python src/syft_mcp_server.py`
    - SBOM 취약점 스캔 서버: `python src/grype_mcp_server.py`
    - 대시보드 데이터 생성 서버: `python src/dashboard_mcp_server.py`
- 대시보드 실행:
    ```bash
    streamlit run src/dashboard.py
    ```

### 5. 입력/출력 파일 구조 예시
- SBOM 파일: CycloneDX/JSON 등
- 취약점 스캔 결과: `latest_scan_result.json`

### 6. 사용 예시 및 워크플로우
1. 코드 저장소 클론
2. Syft로 SBOM 생성
3. Grype로 SBOM 취약점 스캔
4. Vuln Manage MCP로 패치 우선순위 산출
5. Dashboard MCP로 대시보드 데이터 생성
6. Streamlit 대시보드 실행 및 확인

### 7. 라이선스 및 참고 자료
- 본 프로젝트는 오픈소스 라이선스를 따릅니다.
- 참고: [Syft 공식문서](https://anchore.github.io/syft/), [Grype 공식문서](https://anchore.github.io/grype/)
