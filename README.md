# Phantom [<!--lint ignore no-dead-urls-->![main workflow](https://github.com/neil-smyth/phantom/actions/workflows/main_cmake.yml/badge.svg)](https://github.com/neil-smyth/phantom/actions?workflow=Main) [<!--lint ignore no-dead-urls-->![cpplint workflow](https://github.com/neil-smyth/phantom/actions/workflows/cpplint.yml/badge.svg)](https://github.com/neil-smyth/phantom/actions?workflow=Cpplint)

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

<br></br>

<figcaption align = "center"><b>Table 1 - Currently supported public key cryptosystems</b></figcaption>

| Type | Algorithm | Status |
| ---- | --------- | ------ |
| Signatures                | Dilithium<sup>1</sup> | Functional, requires KAT tests for validation |
| Signatures                | Falcon<sup>1</sup> | Functional, requires KAT tests for validation |
| Signatures                | RSASSA-PSS<sup>2</sup> | Functional, requires optimization |
| Signatures                | ECDSA | Functional (NIST, SECG) |
| Signatures                | EDDSA | Functional (ed25519, ed448) |
| KEM                       | Kyber<sup>1</sup> | Functional, requires KAT tests for validation |
| KEM                       | SABER<sup>1</sup> | Functional, requires KAT tests for validation |
| Encryption                | Kyber<sup>1</sup> | Functional, requires KAT tests for validation |
| Encryption                | SABER<sup>1</sup> | Functional, requires KAT tests for validation |
| Encryption                | RSAES-OAEP<sup>2</sup> | Functional, requires optimization |
| Key Exchange              | ECDH | Functional (NIST, SECG, Curve25510, Curve448) |
| Identity Based Encryption | DLP (experimental) | Experimental |
| Identity Based Signature  | DLP (experimental) | Experimental |

> <sup>1</sup> Requires update to latest/final NIST submission

> <sup>2</sup> RSA exponentiation algorithms require optimisation

<br></br>

<figcaption align = "center"><b>Table 2 - Currently supported miscellaneous cryptosystems</b></figcaption>

| Type | Algorithm | Status |
| ---- | --------- | ------ |
| Format Preserving Encryption        | AES-FPE-FF1     | Compliant with NIST test vectors  |
| Format Preserving Encryption        | AES-FPE-FF3-1   | Require NIST test vectors to test |
| Encryption                          | AES-CTR         | Compliant with NIST test vectors  |
| Authenticated Encryption            | AES-CCM         | Compliant with NIST test vectors  |
| Authenticated Encryption            | AES-GCM         | Compliant with NIST test vectors  |
| Cryptographic Hash                  | SHA-2           | Compliant with NIST test vectors  |
| Cryptographic Hash                  | SHA-3           | Compliant with NIST test vectors  |
| Extendable-output function (XOF)    | SHAKE           | Compliant with NIST test vectors  |
| Secret sharing                      | Shamir's scheme | Functional                        |

<br></br>

## Third-Party Libraries

This software makes use of the following open source libraries:

1. JSON for Modern C++ (https://github.com/nlohmann/json) [MIT license]
2. Base64 encoding and decoding with C++ (https://github.com/ReneNyffenegger/cpp-base64) [proprietary permissive license]


## License

This software is MIT licensed. Please see the attached _LICENSE_ file.


## Build & Install

CMake should be used to build and install the library using an out-of-source build: create a folder within the root directory of the project (or elsewhere) and change directory to it, run cmake using the script in the root directory and then use make to build and then optionally run the tests if they are enabled. A static and shared library will be built by default together with all available cryptographic algorithms.

The following will create and test an optimised release build supporting all available cryptographic algorithms:

```
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON ..
cmake --build .
ctest
```

A specific set of algorithms can be included in the library. For example, the following will build a library supporting AES-FF1 Format Preserving Encryption only:

```
cmake -DENABLE_ALL=OFF -DENABLE_FPE_AES_FF1=ON ..
cmake --build .
```

Algorithms are also logically grouped allowing them to be enabled/disabled within those groups. For example, the following will build all available algorithms except all KEM cryptosystems:

```
cmake -DENABLE_ALL=ON -DENABLE_PKC_KEM=OFF ..
cmake --build .
```


A number of toolchain files are provided principally for cross-compiling and allowing the user to control the compiler and its settings. The following example toolchains are provided (these are also used for CI build testing):

* [x86 | x86-64] Linux [GNU | Clang | Intel DPC++]
* [x86 | x86-64] Windows [MSVC | MinGW]
* ARM64 Linux GNU


The toolchain file can be selected using the _CMAKE_TOOLCHAIN_FILE_ option:

```
cmake -DCMAKE_TOOLCHAIN_FILE=x86_linux.gnu.cmake ..
```

## Bindings

The library is written in C++. For portability a range of C wrappers are provided in the _bindings_ directory together with bindings for other languages that use the C interface of the _Phantom_ shared library.


## Performance Metrics

This is a big item on the TODO list - the functional tests in the _test_ directory provide some timing and performance information. An automated test executable to generate the metrics and associated documentation is needed. I have Proxmox Epyc and Xeon servers available that may be configured with suitable OS and hardware settings in a VM to provide repeatable test results.


## Static Analysis

Support for _Cpplint_ is provided if the cmake project detects the presence of of the _Cpplint_ parser. If so, static analysis of the source code can be conveniently performed using the target _cpplint_, for example:

```
cmake --build . --target cpplint
```

## Reference Manual

Documentation for developers describing the library software is contained in the reference manual _<build directory>/docs/phantom_reference.pdf_. This document is built using Doxygen using the _make_doc_ target within your build directory, Doxygen will also produce an html version of the reference manual.

Creating the documentation requires that the following prerequisite software packages are installed:
* Doxygen (e.g. _sudo apt install doxygen_)
* An extended range of LaTeX configuration files typically used by Doxygen (e.g. _sudo apt install texlive-extra_)
* _It is recommended that the Graphviz/Dot UML plotting tool is also installed, but this is not necessary_ (e.g. _sudo apt install graphviz_)
