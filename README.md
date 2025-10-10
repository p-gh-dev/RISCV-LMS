# MA_LMS
LMS implementation adapted from Cisco with SHA-3.
## Compiling
The LMS program can be compiled using either the internal SHA-2 and Brainhub SHA-3 implementation or using OpenSSL. The switch for this can be found in sha256.h as USE_OPENSSL. All hash functions use the IUF (Init, Update, Finalize) paradigm.

Two makefiles are included, the default Makefile for x86 and the Makefile_rv64gc for RISC-V RV64GC cores. The tests have not been expanded to SHA-3 yet so will throw errors if not commented out (test_1 and test_hss). The final programs to run will be demo for multithreaded (default 16) and demo_st for singlethreaded.
## CLI Syntax
The program is run from the command line as follows:

Generating a key:

demo genkey keyname -- generates public/private key with default parameters

demo genkey keyname sha2/15/4,sha2/15/4:2000 -- generate public/private key with specific parameters (SHA-2, height 15, winternitz 4 for first and second trees, up to 2000 bytes of aux data). Possible values are sha2 or sha3, [5,10,15,20], [1,2,4,8].

Signing:

demo sign keyname file -- signs file with provided key

Verifying:

demo verify keyname file -- verifies file.sig with provided key

## Testing so far
Tests have been run using test_script.sh in Testing, the commands run are as follows:

perf stat -o "output_file_gk.txt" ./demo genkey keyname sha2/5/1 (iterated over all parameters)

perf stat -o "output_file_sg.txt" ./demo sign keyname lipsum

perf stat -o "output_file_vf.txt" ./demo verify keyname lipsum
