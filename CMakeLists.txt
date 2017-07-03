cmake_minimum_required(VERSION 3.5)
project(paranoid)

set(CMAKE_C_STANDARD 99)

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

include_directories(src/include)

add_executable(paranoid ${CONTAINER_SOURCE_FILES} src/paraniod.c)
target_link_libraries(paranoid pthread cap seccomp cgroup)
