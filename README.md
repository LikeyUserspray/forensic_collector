# Forensics_collector
# 윈도우 포렌식 아티팩트 수집기

다운로드 : https://1drv.ms/u/s!Auf4B-HCySk0j21f55RoElPr0ItT?e=rs2LeW

파일 이름 : Forensic_Artifact_Proj-6

압축 해제 비밀번호 : KDT3rdProject

사용 오픈 소스
- 반디집
- Achoir
- FLTK


사용 방법 : 
압축파일 해제 후 "관리자 권한으로" collect_artifacts.exe 실행 
![2772272](https://github.com/LikeyUserspray/forensic_collector/assets/98539049/57ff0ce5-cba8-4910-961f-a95a58c46a3e)

- 기능 :
  
    1. 담당 수사관 및 날짜 입력 → input 버튼 누르면 해당 부분은 수정할 수 없다.
        - 여기서는 txt로 저장하기 전까지만 수정되지 못하게 처리하였지만, txt를 read only로 저장하게 수정한 코드를 cpp로 올려두었습니다.
          
        ![vsavsda](https://github.com/LikeyUserspray/forensic_collector/assets/98539049/8309cb0b-182d-4f22-a7da-468959438adf)
       
            
    3. 원하는 정보를 체크 → Export → Artifacts 디렉터리 내부에 저장 됨.
        - 원하는 정보를 체크 하면 Artifacts 디렉터리 내부에 각 파일 별로 저장.
        - Artifacts를 반디집을 통해서 Artifacts 파일을 압축해서 추가 저장.
          
        ![qqweqwe](https://github.com/LikeyUserspray/forensic_collector/assets/98539049/5abc1824-fa1a-494b-87ed-0f96a92db6aa)
  
       ![fdabdbfba](https://github.com/LikeyUserspray/forensic_collector/assets/98539049/b04bba32-0390-4e73-a87c-c1b20878c301)
       

    5. According to Event ID 기능
        - 이벤트 로그 등에서 해당 기능과 관련된 정보들만 모아서 .txt 리스트로 모으는 기능.
    6. Search 기능.
        - Artifacts 내부의 정보를 검색하는 기능
        - Search 기능이 버퍼를 통해서 검색하는데, Memory Full Dump(Ram 덤프) 파일은 용량이 너무 커서 예외 처리를 통해 검색이 되지 않습니다.
          
          ![vavvavvavav](https://github.com/LikeyUserspray/forensic_collector/assets/98539049/51b15356-1f30-497a-9df9-a625669c0763)
          

