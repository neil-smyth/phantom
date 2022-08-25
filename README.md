# Phantom

A C++ library for application level cryptography with a design goal of employing secure software best practices. Created initially for fun and learning, this has evolved and is now being used in other projects. The code base is targeted at generic C++11 with support for variable machine word length.

_Phantom_ provides implementations of established and bleeding edge cryptographic algorithms, with a view to providing usability, portability and performance while providing a modular and extensible architecture. I want to be able to add new or modified implementations of algorithms in a simple and non-invasive manner. This library provides a practical solution for applications that require a range of cryptographic operations - particularly those using new or unsupported cryptosystems.

The focus is currently to build for x86_64 with GNU compiler and Linux, There is no optimization for specific CPUs other than for the machine word size. Future support is planned for the following:
* GNU, Clang, Intel and MSVC compilers
* Linux, OSX and Windows operating system's
* Assembler optimisation for 32/64-bit Intel and 32/64-bit ARM
* API changes to permit integration with hardware security devices for CSPRNG, key generation and storage, crypto processing, etc. (specifically I want to integrate my Nitrokey HSM...)
* Bindings in at least C# and Python for the whole _Phantom_ API
* Add some new cryptosystems (zero-knowledge proof's, maybe not SIKE...)
* More testing and options for CSPRNG's

The following public key cryptosystems are currently supported:

Signatures:
1. Dilithium (requires update to latest/final NIST submission)
2. Falcon (requires update to latest/final NIST submission)
3. RSASSA-PSS (RSA exponentiation algorithms require optimisation)
4. ECDSA
5. EDDSA

KEM:
1. Kyber (requires update to latest/final NIST submission)
2. Saber (requires update to latest/final NIST submission)

Public-Key Encryption:
1. Kyber (requires update to latest/final NIST submission)
2. Saber (requires update to latest/final NIST submission)
3. RSAES-OAEP (RSA exponentiation algorithms require optimisation)

Key Exchange:
1. ECDH

Identity-Based Encryption:
1. DLP (experimental)

Identity-Based Signatures:
1. DLP (experimental)

The following symmetric cryptosystems are available:

1. Format Preserving Encryption (AES-FPE-FF1, AES-FPE-FF3-1)
2. AES (AES-CTR, AES-GCM)


The following cryptographic hash functions and message authentication codes are available:

1. SHA-2 (SHA-224, SHA-256, SHA-384, SHA-512)
2. SHA-3 (SHA3-224, SHA3-256, SHA3-384, SHA3-512)
3. SHAKE-128, SHAKE-256


The following secret sharing schemes are available:

1. Shamir's scheme


## Third-Party Libraries

This software makes use of the following open source libraries:

1. JSON for Modern C++ (https://github.com/nlohmann/json) [MIT license]
2. Base64 encoding and decoding with C++ (https://github.com/ReneNyffenegger/cpp-base64) [proprietary permissive license]


## License

This software is MIT licensed. Please see the attached _LICENSE_ file.


## Build & Install

CMake should be used to build and install the library using an out-of-source build: create a folder within the root directory of the project (or elsewhere) and change directory to it, run cmake using the script in the root directory and then use make to build and then run the tests.

```
mkdir build && cd build
cmake ..
make
make test
```

A number of toolchain files are provided principally for cross-compiling and allowing the user to control the compiler and its settings. The following example toolchains are provided (these are also used for CI build testing):

* 32/64-bit Linux GNU
* 32/64-bit Linux Clang

The toolchain file can be selected using the _CMAKE_TOOLCHAIN_FILE_ option:

```
_cmake -DCMAKE_TOOLCHAIN_FILE=x86_linux.gnu.cmake .._
```

## Bindings

The library is written in C++. For portability a range of C wrappers are provided in the _bindings_ directory together with bindings for other languages that use the C interface of the _Phantom_ shared library.


## Performance Metrics

This is a big item on the TODO list - the functional tests in the _test_ directory provide some timing and performance information. An automated test executable to generate the metrics and associated documentation is needed. I have Proxmox Epyc and Xeon servers available that may be configured with suitable OS and hardware settings in a VM to provide repeatable test results.


## Static Analysis

Support for _Cpplint_ is provided if the cmake project detects the presence of of the _Cpplint_ parser. If so, static analysis of the source code can be conveniently performed using the target _cpplint_, for example:

```
_make cpplint_
```

## Reference Manual

Documentation for developers describing the library software is contained in the reference manual _<build directory>/docs/phantom_reference.pdf_. This document is built using Doxygen using the _make_doc_ target within your build directory, Doxygen will also produce an html version of the reference manual.

Creating the documentation requires that the following prerequisite software packages are installed:
* Doxygen (e.g. _sudo apt install doxygen_)
* An extended range of LaTeX configuration files typically used by Doxygen (e.g. _sudo apt install texlive-extra_)
* _It is recommended that the Graphviz/Dot UML plotting tool is also installed, but this is not necessary_ (e.g. _sudo apt install graphviz_)
