cmake_minimum_required(VERSION 3.10)

# 프로젝트 이름 및 언어 설정
project(ACClient CXX)

# C++17 표준 사용 설정 (C++20을 원하실 경우 17을 20으로 변경하세요)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 서버 스레드 처리를 위한 Threads(pthread) 패키지 찾기
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# libsodium 라이브러리 찾기
find_path(SODIUM_INCLUDE_DIR sodium.h)
find_library(SODIUM_LIBRARY sodium)

# libsodium이 시스템에 없을 경우 에러 메시지 출력
if(NOT SODIUM_LIBRARY)
    message(FATAL_ERROR "❌ libsodium 라이브러리를 찾을 수 없습니다. 설치를 확인해주세요. (예: sudo apt-get install libsodium-dev)")
endif()

# 헤더 파일 경로 포함
include_directories(${SODIUM_INCLUDE_DIR})

# 클라이언트 실행 파일 타겟 설정
add_executable(client client.cpp)
# 클라이언트는 libsodium만 링크
target_link_libraries(client PRIVATE ${SODIUM_LIBRARY})
