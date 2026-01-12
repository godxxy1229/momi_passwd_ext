# Momi Password Extractor

실행 중인 맘아이(Momi) 관련 프로세스의 메모리를 스캔하여 비밀번호를 추출하는 도구입니다.

## 조건
1. 맘아이 실행 후, 관리자가 비밀번호를 입력해야 합니다.
2. 비밀번호가 입력되었다면, 맘아이 프로그램을 종료하기 전에 코드를 실행하면 비밀번호를 찾을 수 있습니다.
  - 비밀번호 입력 후에 실행해도 문제 없이 찾을 수 있습니다.
3. 비밀번호 입력 후, 맘아이를 재시작한 뒤 코드를 실행하면 비밀번호를 찾을 수 없습니다. (재부팅 포함)
  - 맘아이 재시작시 프로세스 메모리에 남아있던 비밀번호가 사라집니다.

## 기능
- 버튼을 클릭해 맘아이 관련 프로세스를 자동으로 탐색하고 비밀번호를 추출합니다.
- 맘아이 버전이 달라질 경우 동작하지 않을 수 있습니다. (5.0 버전을 기준으로 작성됨)

## 사용 방법
1. 미리 빌드된 exe 파일로 실행합니다: [mamai_passwd_oneclick.exe](https://github.com/godxxy1229/momi_passwd_ext/releases/download/v0.0.1/mamai_passwd_oneclick.exe)
2. Python이 설치된 환경에서 momi_passwd_oneclick.py을 실행합니다. (python momi_passwd_oneclick.py)

## References
- [MomiCrack](https://github.com/PragmoB/MomiCrack)을 참고했습니다.

## 주의사항
- 이 코드는 프로세스 메모리를 읽기 위해 관리자 권한이 필요합니다.
- 학습을 목적으로 작성했습니다. 악용 시 발생하는 모든 책임은 사용자에게 있습니다.
