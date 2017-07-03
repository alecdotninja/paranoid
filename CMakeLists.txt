cmake_minimum_required(VERSION 3.5)
project(paranoid)

set(CMAKE_C_STANDARD 99)

include_directories(
        src/include
        vendor/libcap/libcap/include
)

set(
        LIBCAP_SOURCE_FILES

        vendor/libcap/libcap/libcap.h
        vendor/libcap/libcap/cap_names.h
        vendor/libcap/libcap/cap_alloc.c
        vendor/libcap/libcap/cap_extint.c
        vendor/libcap/libcap/cap_file.c
        vendor/libcap/libcap/cap_flag.c
        vendor/libcap/libcap/cap_proc.c
        vendor/libcap/libcap/cap_text.c
)

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/vendor/libcap/libcap/cap_names.h
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/vendor/libcap/libcap
        COMMAND make cap_names.h
)

set(
        CONTAINER_SOURCE_FILES

        src/include/container/container.h
        src/container/container.c

        src/include/container/fs.h
        src/container/fs.c

        src/include/container/init.h
        src/container/init.c

        src/include/container/networking.h
        src/container/networking.c

        src/include/container/plumbing.h
        src/container/plumbing.c

        src/include/container/signaling.h
        src/container/signaling.c

        src/include/container/spawn.h
        src/container/spawn.c

        src/include/container/tty.h
        src/container/tty.c

        src/include/container/unsafe.h
        src/container/unsafe.c

        src/include/container/userns.h
        src/container/userns.c
)

add_executable(paranoid ${LIBSECCOMP_SOURCE_FILES} ${LIBCAP_SOURCE_FILES} ${CONTAINER_SOURCE_FILES} src/paraniod.c)

target_link_libraries(paranoid pthread cgroup)
