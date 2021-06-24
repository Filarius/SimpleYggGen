file(GLOB ${PROJECT_NAME}_SOURCES *.cpp)
file(GLOB ${PROJECT_NAME}_HEADERS *.h)
file(GLOB_RECURSE ${PROJECT_NAME}_HEADERS cppcodec/*.hpp)

list(APPEND ${PROJECT_NAME}_SOURCES floodyberry-ed25519-donna/ed25519.c)
list(APPEND ${PROJECT_NAME}_HEADERS floodyberry-ed25519-donna/ed25519.h)

if(WIN32)
    list(APPEND ${PROJECT_NAME}_SOURCES "windows/resource.rc")
endif()

set(${PROJECT_NAME}_DEPS
    ${${PROJECT_NAME}_SOURCES}
    ${${PROJECT_NAME}_HEADERS}
)

set(ADD_FLAGS "-m64 -O3")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ADD_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${ADD_FLAGS}")

find_package(OpenSSL REQUIRED)
if(NOT DEFINED OPENSSL_INCLUDE_DIR)
  message(SEND_ERROR "Could not find OpenSSL. Please download and install it first!")
endif()

set(THREADS_PREFER_PTHREAD_FLAG ON)
if(IOS)
  set(CMAKE_THREAD_LIBS_INIT "-lpthread")
  set(CMAKE_HAVE_THREADS_LIBRARY 1)
  set(CMAKE_USE_WIN32_THREADS_INIT 0)
  set(CMAKE_USE_PTHREADS_INIT 1)
else()
  find_package(Threads REQUIRED)
endif()
if(THREADS_HAVE_PTHREAD_ARG) # compile time flag
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif()

add_executable(${PROJECT_NAME} ${${PROJECT_NAME}_DEPS})
target_link_libraries(${PROJECT_NAME} sodium)

if(WIN32)
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-static")
    target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES} ws2_32)
else()
    add_executable(${PROJECT_NAME} ${${PROJECT_NAME}_DEPS})
    target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
endif()

