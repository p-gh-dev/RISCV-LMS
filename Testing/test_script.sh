#!/bin/bash

heights=(5 10 15 20)
winternitz=(1 2 4 8)
hashes=(2 3)

logfile="debug_ossl.log"
: > "$logfile"  # Clear the log file

for h in "${heights[@]}"; do
    for w in "${winternitz[@]}"; do
        for hash in "${hashes[@]}"; do
            keyname="ossl_key_l1_h${h}_w${w}_sha${hash}"
            parmset="sha${hash}/${h}/${w}"
            cp lipsum lipsum_"$keyname"_mt 
            cp lipsum lipsum_"$keyname"_st
            gprofng collect app -O mt_genkey_"$keyname".er .././demo genkey "$keyname"_mt "$parmset" >> debug.log
            gprofng collect app -O mt_sign_"$keyname".er .././demo sign "$keyname"_mt lipsum_"$keyname"_mt >> debug.log
            gprofng collect app -O mt_verify_"$keyname".er .././demo verify "$keyname"_mt lipsum_"$keyname"_mt >> debug.log

            gprofng collect app -O st_genkey_"$keyname".er .././demo_st genkey "$keyname"_st "$parmset" >> debug.log
            gprofng collect app -O st_sign_"$keyname".er .././demo_st sign "$keyname"_st lipsum_"$keyname"_st >> debug.log
            gprofng collect app -O st_verify_"$keyname".er .././demo_st verify "$keyname"_st lipsum_"$keyname"_st >> debug.log
        done
    done
done