# Building from the source

!!! Note
    Consider also visiting the following instructions:  
    1. docker container as [building environment](./environment.md)  
    2. building tracker [container images](./containers.md)  

1. Supported **Architectures**

    1. x86_64 (amd64)
    1. aarch64 (arm64)

2. Building **dependencies**

    1. **clang** && **llvm** (12, 13 or 14)
    1. **golang** (1.22.3 toolchain)
    1. **libelf** and **libelf-dev**
       (or elfutils-libelf and elfutils-libelf-devel)
    1. **zlib1g** and **zlib1g-dev**
       (or zlib and zlib-devel)
    1. **libzstd-dev** for static build (libelf linkage)
    1. **clang-format-12** (specific version) for `fix-fmt`

    > You might take a look at the following files to understand how to have a
    > building environment:
    >
    > 1. [.github/actions/build-dependencies/action.yaml](https://github.com/khulnasoft/tracker/blob/main/.github/actions/build-dependencies/action.yaml)
    > 1. [packaging/Dockerfile.ubuntu-packaging](https://github.com/khulnasoft/tracker/blob/main/packaging/Dockerfile.ubuntu-packaging)
    > 1. [packaging/Dockerfile.fedora-packaging](https://github.com/khulnasoft/tracker/blob/main/packaging/Dockerfile.fedora-packaging)
    >
    > Those are very good examples for you to replicate a working environment.

3. **Clone** [tracker repository](https://github.com/khulnasoft/tracker/)

    ```console
    git clone git@github.com:khulnasoft/tracker
    ```

    ```text
    Cloning into 'tracker'...
    remote: Enumerating objects: 13251, done.
    remote: Counting objects: 100% (555/555), done.
    remote: Compressing objects: 100% (240/240), done.
    remote: Total 13251 (delta 343), reused 369 (delta 280), pack-reused 12696
    Receiving objects: 100% (13251/13251), 11.75 MiB | 8.62 MiB/s, done.
    Resolving deltas: 100% (8105/8105), done.
    ```

4. All makefiles have a **help** target to give you needed instructions

    ```console
    make help
    ```

    ```text
    # environment

        $ make env                      # show makefile environment/variables

    # build

        $ make all                      # build tracker-ebpf, tracker-rules & signatures
        $ make bpf                      # build ./dist/tracker.bpf.o
        $ make tracker-ebpf              # build ./dist/tracker-ebpf
        $ make tracker-rules             # build ./dist/tracker-rules
        $ make tracker-bench             # build ./dist/tracker-bench
        $ make signatures               # build ./dist/signatures
        $ make e2e-net-signatures       # build ./dist/e2e-net-signatures
        $ make e2e-inst-signatures      # build ./dist/e2e-inst-signatures
        $ make tracker                   # build ./dist/tracker

    # clean

        $ make clean                    # wipe ./dist/
        $ make clean-bpf                # wipe ./dist/tracker.bpf.o
        $ make clean-tracker-ebpf        # wipe ./dist/tracker-ebpf
        $ make clean-tracker-rules       # wipe ./dist/tracker-rules
        $ make clean-tracker-bench       # wipe ./dist/tracker-bench
        $ make clean-signatures         # wipe ./dist/signatures
        $ make clean-tracker             # wipe ./dist/tracker

    # test

        $ make test-unit                # run unit tests
        $ make test-types               # run unit tests for types module
        $ make test-integration         # run integration tests

    # flags

        $ STATIC=1 make ...             # build static binaries
        $ BTFHUB=1 STATIC=1 make ...    # build static binaries, embed BTF
        $ DEBUG=1 make ...              # build binaries with debug symbols
    ```

5. Build **all** targets at once

    ```console
    make all
    ```

    ```text
    Submodule 'libbpf' (https://github.com/libbpf/libbpf.git) registered for path '3rdparty/libbpf'
    Cloning into '/home/rafaeldtinoco/tracker/3rdparty/libbpf'...
    mkdir -p dist/signatures
    GOOS=linux CC=clang GOARCH=amd64 CGO_CFLAGS= CGO_LDFLAGS= go build \
        --buildmode=plugin \
        -o dist/signatures/builtin.so \
        signatures/golang/export.go signatures/golang/kubernetes_api_connection.go signatures/golang/stdio_over_socket.go
    ```

6. Build a **static binary** by setting `STATIC=1`

    ```console
    STATIC=1 make all
    ```

    ```text
    CC="clang" \
        CFLAGS=""-fPIC"" \
        LD_FLAGS="" \
        make \
        -C ./3rdparty/libbpf/src \
        BUILD_STATIC_ONLY=1 \
        DESTDIR=/home/rafaeldtinoco/tracker/dist/libbpf \
        OBJDIR=/home/rafaeldtinoco/tracker/dist/libbpf/obj \
        INCLUDEDIR= LIBDIR= UAPIDIR= prefix= libdir= \
        install install_uapi_headers
    ...
    ```

7. Build a **static binary** with [BTFHUB Support](https://github.com/khulnasoft/btfhub)

    ```console
    BTFHUB=1 STATIC=1 make all
    ```

    ```text
    Cloning into '/home/rafaeldtinoco/tracker/3rdparty/btfhub'...
    remote: Enumerating objects: 205, done.
    remote: Counting objects: 100% (16/16), done.
    remote: Compressing objects: 100% (12/12), done.
    remote: Total 205 (delta 4), reused 10 (delta 3), pack-reused 189
    Receiving objects: 100% (205/205), 10.59 MiB | 7.56 MiB/s, done.
    Resolving deltas: 100% (73/73), done.
    Cloning into '/home/rafaeldtinoco/tracker/3rdparty/btfhub-archive'...
    remote: Enumerating objects: 1993, done.
    remote: Counting objects: 100% (28/28), done.
    remote: Compressing objects: 100% (23/23), done.
    Receiving objects:  15% (301/1993), 154.97 MiB | 15.72 MiB/s
    ```

    !!! Note
        BTFHUB support will embed several very small files (BTF files) into your
        final binary. Those files will allow **tracker** binary to be executed
        in kernels that doesn't have embedded BTF information (the ones described
        at the BTFHUB repository)

    !!! Attention
        compiling `tracker-rules` with STATIC=1 won't allow you to use golang based
        signatures as plugins, only as built-ins:
        >```text
        >2021/12/13 13:27:21 error opening plugin /tracker/dist/signatures/builtin.so:
        >plugin.Open("/tracker/dist/signatures/builtin.so"): Dynamic loading not supported
        >```

8. Build a **debugable binary** with DWARF generation by setting `DEBUG=1`

    ```console
    DEBUG=1 make
    ```
    
    ```text
    GOOS=linux CC=clang GOARCH=amd64 CGO_CFLAGS="-I/home/gg/code/tracker/dist/libbpf" CGO_LDFLAGS="-lelf  -lz  /home/gg/code/tracker/dist/libbpf/libbpf.a" go build \
        -tags core,ebpf \
        -ldflags=" \
             -extldflags \"\" \
             -X main.version=\"v0.8.0-107-g121efeb\" \
            " \
        -v -o dist/tracker \
       ./cmd/tracker
    ```
