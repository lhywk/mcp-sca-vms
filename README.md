# MCP-SCA-VMS
이 시스템은 Github 저장소 레포지토리의 소프트웨어 구성 요소 분석(SCA) 및 취약점 관리 자동화를 위한 MCP 기반 시스템입니다.

### 주요 기능
- 코드 저장소 자동 클론 및 SBOM(Software Bill of Materials) 생성
- SBOM 기반 취약점 탐지 및 위험도 평가
- EPSS, CVSS 등 Grype 기반 패치 우선순위 산출
- CVE ID에 대한 상세 정보 제공
- Streamlit 기반 대시보드로 시각화

### 필수 소프트웨어 및 환경
- Python 3.10 이상
- Syft, Grype 등 외부 CLI 도구
    - [Syft 설치 안내](https://github.com/anchore/syft#installation)
    - [Grype 설치 안내](https://github.com/anchore/grype#installation)

### 의존성 설치 (uv 권장)
1. uv 설치 (최초 1회만)
    ```bash
    pip install uv
    ```
2. 패키지 설치
    ```bash
    uv pip install -r requirements.txt
    ```
3. (가상환경 사용 시) 가상환경을 먼저 활성화한 뒤 위 명령어를 실행하세요.


### 실행 방법

먼저, 명령 프롬프트(cmd) 창에 아래 명령어를 입력해 MCP 서버를 실행하세요:

```bash
uvx --from git+https://github.com/lhywk/mcp-sca-vms.git mcp-server
```

또는, `claude_desktop_config.json` 파일에 아래와 같이 설정을 추가하세요:

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

- 대시보드 실행:
        ```bash
        streamlit run src/dashboard.py
        ```

### 프롬프트 예시 및 전체 워크플로우

먼저, `[레포지토리 URL]` 해당 레포지토리를 `[디렉터리 경로]` 경로에 클론하고, Syft를 이용해 SBOM을 생성합니다.
다음으로, Grype의 취약점 데이터베이스를 최신 상태로 업데이트한 후, 생성된 SBOM을 스캔하여 취약점을 탐지합니다.
마지막으로, 탐지된 취약점의 패치 우선순위를 분석하고 모든 최종 결과를 Streamlit 대시보드로 시각화합니다.

### 라이선스 및 참고 자료
- 본 시스템은 오픈소스 라이선스를 따릅니다.
- 참고: [Syft 공식문서](https://anchore.github.io/syft/), [Grype 공식문서](https://anchore.github.io/grype/)
