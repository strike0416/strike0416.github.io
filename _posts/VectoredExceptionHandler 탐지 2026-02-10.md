---
title: VectoredExceptionHandler 탐지
date: 2026-02-10 14:53:00 +0900
categories: [Security, Reversing]
tags: [reversing]
author: strike0416
---

# VectoredExceptionHandler 탐지

---

# VectoredExceptionHandler란?

---

VectoredExceptionHandler(이하 VEH)는 SEH보다 우선적으로 실행되는 전역 예외 핸들러이다.

프로세스 내에서 발생하는 모든 예외(access violation, breakpoint)를 최우선으로 가로챌 수 있다.

Windows에서 예외 발생시 처리 순서는 고정되어 있는데, 아래와 같다.

1. VectoredExceptionHandler (VEH)
2. StructuredExceptionHandling (SEH)
3. UnhandledExceptionFilter

VEH는 디버거 구현, 안티 디버깅, 안티 치트, API 후킹 등을 위해 사용된다. 

일반적으로 VEH는 아래와 같은 코드를 통해 사용할 수 있다.

```jsx
LONG CALLBACK ExceptionHandler(PEXCEPTION_POINTERS e);
AddVectoredExceptionHandler(1, ExceptionHandler);//1이면 FirstHandler
```

더 자세한 정보는 https://learn.microsoft.com/ko-kr/windows/win32/api/winnt/nc-winnt-pvectored_exception_handler 에서 확인 가능하다.

# RtlAddVectoredExceptionHandler 함수 분석

---

`AddVectoredExceptionHandler`함수를 실제로 써보면 `RtlAddVectoredExceptionHandler`로 포워딩 돼있는 것을 확인 가능하다. 

이제 ida를 사용해서 `RtlAddVectoredExceptionHandler` 함수를 분석해보자.

분석해보면 `LdrpVectorHandlerList`라는 변수에 핸들러 목록이 저장되는 것을 확인 가능하다.

![](https://github.com/strike0416/Detect-VEH/raw/main/imgs/LdrpVectorHandlerList_ida.png)

`83 E0 3F 48 8D 3D`  패턴 스캔을 통해 타 윈도우 버젼 (win10 22H2)에서도 찾을 수 있음을 확인했다.

# Handler 구조체

---

VectoredHandlerList의 구조는 아래와 같다. 

어떠한 핸들러도 등록되있지 않은 경우, `LdrpVectorHandlerList + 0x8`의 값이 first_exception_handler에 저장되어 있음을 확인 가능했다. 이를 통해 등록되있지 않은 경를 수이 구분 가능하다.

```jsx
typedef struct _VECTORED_HANDLER_ENTRY
{
	LIST_ENTRY entry;
	PVOID refs;
	PVOID unknown;
	PVECTORED_EXCEPTION_HANDLER encoded_handler;
} VECTORED_HANDLER_ENTRY, *PVECTORED_HANDLER_ENTRY;

typedef struct _VECTORED_HANDLER_LIST
{
	PVOID mutex_exception;
	PVECTORED_HANDLER_ENTRY first_exception_handler;
	PVECTORED_HANDLER_ENTRY last_exception_handler;
	PVOID mutex_continue;
	PVECTORED_HANDLER_ENTRY first_continue_handler;
	PVECTORED_HANDLER_ENTRY last_continue_handler;
} VECTORED_HANDLER_LIST, *PVECTORED_HANDLER_LIST;
```

핸들러의 주소값을 찾는 것이 목적인데, 해당 주소 값은 process cookie를 통해 encode 되어있다.

RtlDecodePointer 함수 분석을 통해 간단히 decode 방법을 찾을 수 있다.

```jsx
std::uint64_t decode_pointer(std::uint64_t ptr, std::uint32_t process_cookie)
{
	return _rotr64(ptr, 64 - (process_cookie & 0x3F)) ^ process_cookie;
}
```

ida로 RtlDecodePointer 함수를 분석 도중, process cookie가 cache된 부분을 발견했다.

![](https://github.com/strike0416/Detect-VEH/raw/main/imgs/RtlDecodePointer_ida.png)

cache된 process cookie를 가져올시 타 프로세스의 VEH 핸들러 목록도 쉽게 탐지 가능해 보인다.

자세한 코드는 github으로.

[https://github.com/strike0416/Detect-VEH](https://github.com/strike0416/Detect-VEH)

## 참조

---

[https://dimitrifourny.github.io/2020/06/11/dumping-veh-win10.html](https://dimitrifourny.github.io/2020/06/11/dumping-veh-win10.html)