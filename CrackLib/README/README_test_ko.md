# Crack! AES1 vs CRACK_AES 기능 데모 및 성능 비교 프로그램 사용설명서 (test.c)

## 1. 개요

**test.c**는 Crack! 프로젝트에서 구현한 AES1(속도형) 과
CRACK_AES(AES2, 보안형) 암호 프로파일을 직접 비교·체험하기 위한
통합 데모 + 벤치마크 프로그램입니다.

본 프로그램은 다음 목적을 갖습니다.

-  AES 운용 모드별 동작 방식 이해 (ECB / CBC / CTR) 
-  보안형 CRACK_AES의 EtM(Encrypt-then-MAC) 구조 실습
-  동일 환경에서의 성능(처리량 MB/s) 비교
-  nonce / IV / tag 등 실제 통신 메타데이터 구조 확인

지원 언어: **C99**  
의존 라이브러리: 표준 C 라이브러리
                     Crack! 메시지 전송 보안 라이브러리 소스
                       - aes.c / aes.h
                       - crack_aes.c / crack_aes.h
                       - sha512.c / sha512/h
플랫폼 의존성 (난수 생성): Windows BCryptGenRandom, macOS arc4random_buf, Linux /dev/urandom

---

## 2. 빌드 방법

### 2.1 Linux / macOS 빌드 예시
```bash
clang aes.c crack_aes.c sha512.c test.c -O3 -std=c99 -Wall -Wextra -pedantic -o test
./test
```

### 2.2 Windows 실행 파일 직접 빌드
 ```bat
cl /utf-8 /std:c17 /O2 /W4 /D_CRT_SECURE_NO_WARNINGS test.c aes.c crack_aes.c sha512.c bcrypt.lib
```

빌드 결과:

 ```text
test.exe
```

---

## 3. 프로그램 실행 흐름 개요

**test.c**는 메뉴 기반 대화형 구조로 동작하며, 실행 시 다음 순서를 따릅니다.

### 3.1 초기 실행 단계

1. 프로그램 시작 및 배너 출력
2. **[SELFTEST] SHA-512 / CRACK_AES selftest 수행**
3. Self-test 결과 출력 ('OK' 또는 실패 메시지)

### 3.2 상위 모드 선택

```scss
[1] 데모 모드
    (평문 입력 후 암호화/복호화 데모)
[2] 성능 비교 벤치마크
    (AES1 vs CRACK_AES 처리량 비교)
```

사용자는 실행할 모드를 선택합니다.

### 3.3 데모 모드 ([1]) 실행 흐름

데모 모드는 **하나의 메시지에 대해 선택한 암호 프로파일을 적용**하는 구조입니다.

1. **평문 입력**
   - 최대 2047바이트
   - 사용자 입력 문자열을 그대로 암호화 대상 데이터로 사용
2. **프로파일 선택 메뉴 출력**
```scss
[1] AES1 속도형 (CTR / ECB / CBC)
[2] CRACK_AES 보안형 (CTR + HKDF + HMAC-SHA-512)
```
3. **사용자가 프로파일 선택**
4. 선택된 프로파일에 따라 암호화/복호화 데모 수행
5. 결과 출력
  - 암호문
  - nonce / IV / (tag)
  - 복호화 결과 검증

### 3.4 성능 비교 벤치마크 ([2]) 실행 흐름

성능 비교 모드는 사용자 입력 없이 자동 수행됩니다.

1. **고정 크기 데이터(10MiB) 생성**
2. **동일 조건에서 다음 두 프로파일 실행**
   - AES1-CTR
   - CRACK_AES-CTR (EtM 포함)
3. **암호화 소요 시간 측정**
4. **처리량(MB/s) 계산 및 출력**

---

## 4. AES1 (속도형) 데모 설명

AES1은 기밀성만 제공하는 성능 중심 암호화 프로파일입니다.

### 4.1 AES1-CTR 모드 데모

- 패딩 없음
- 암·복호화 동일 함수('AES_cryptCTR') 사용
- 데모에서는 고정 nonce 사용

출력 정보:
- nonce (16바이트)
- ciphertext (HEX)
- 복호화 결과
- (벤치마크 모드) 처리량(MB/s)

CTR 모드는 (key, nonce) 재사용 시 심각한 보안 취약점이 발생합니다.
본 데모의 고정 nonce는 교육·성능 비교 목적이며, 실사용 시에는 반드시 랜덤/유일 nonce를 사용해야 합니다.

### 4.2 AES1 – ECB 모드 데모 (교육용)

- **사용자 선택 패딩**
  - PKCS#7
  - ANSI X9.23
  - NONE
- **블록 단위 독립 암호화**

ECB 모드는 패턴 누출이 발생하므로 실제 환경에서는 사용해서는 안 됩니다.

### 4.3 AES1 – CBC 모드 데모

- 사용자 선택 패딩
- IV 사용 (데모에서는 랜덤 생성)
- IV + ciphertext 출력

CBC는 ECB보다 안전하지만 무결성 보호가 없으므로 실무 환경에서는 단독 사용이 권장되지 않습니다.

---

## 5. CRACK_AES (보안형) 데모

CRACK_AES는 AES1의 한계를 보완한 보안 강화 프로파일입니다.

### 5.1 설계 특징

- HKDF-SHA-512 기반 키 분리
  - 'master_key' → 'Kenc' / 'Kmac'
- Encrypt-then-MAC(EtM) 구조
- HMAC-SHA-512 무결성 검증
- nonce 재사용 가드(Nonce Guard)

### 5.2 CRACK_AES – CTR 보안형 데모

데모 모드에서 CRACK_AES를 선택하면 다음 흐름이 수행됩니다.

1. 마스터 키 및 KDF 파라미터 설정
2. 'CRACK_AES_init_hardened()' 로 보안 컨텍스트 초기화
3. 라이브러리 내부에서 nonce 자동 생성
4. AES-CTR 암호화 수행
5. 'AAD || nonce || ciphertext'에 대해 HMAC 생성
6. 수신 측에서 태그 검증 후 복호화 수행

출력 정보:
- nonce (16 bytes)
- ciphertext
- MAC tag (16 또는 32 bytes)
- 복호화 결과

태그 검증 실패 시:
- 'AES_ERR_AUTH' 반환
- 복호화 결과는 출력·사용되지 않음

---

## 6. 성능 벤치마크 설명

### 6.1 측정 조건

- 데이터 크기: **10 MiB**
- 측정 대상: AES1-CTR, CRACK_AES-CTR (EtM 포함)
- 시간 측정: 'clock()'
- 결과 단위: MB/s

### 6.2 해석 포인트

- AES1-CTR은 항상 더 빠른 처리량을 보임
- CRACK_AES는 다음 연산으로 인한 성능 비용이 발생
  - HMAC 계산
  - 키 파생(HKDF)
  - nonce 재사용 검사

이는 의도된 설계 차이이며, "속도 vs 보안" 트레이드오프를 명확히 보여줍니다.

---

## 7. test.c의 역할 요약

'test.c'는 다음을 수행하는 **통합 실험 드라이버**입니다.

- AES1과 CRACK_AES의 구조적 차이 시연
- 메뉴 기반 선택 실행을 통한 사용성 검증
- 보안 설계 의도 검증
- 성능 차이의 실측 비교

즉 'test.c'는 **Crack! 라이브러리의 사용법을 실행 형태로 보여주는 참고 구현**입니다.

---

이 문서는 이 문서는 Crack! 메시지 전송 보안 라이브러리의 기능과 설계 의도를
**실제 실행 가능한 데모 프로그램(test.c)**을 통해 설명하기 위한 사용 가이드입니다..
