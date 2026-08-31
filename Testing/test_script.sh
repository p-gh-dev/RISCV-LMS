#!/bin/bash

heights=(5 10 15 20)
winternitz=(1 2 4 8)
hashes=(2 3)

logfile="debug.log"
: > "$logfile"  # Clear the log file

for h in "${heights[@]}"; do
    for w in "${winternitz[@]}"; do
        for hash in "${hashes[@]}"; do
            keyname="csit_ossl_key_l1_h${h}_w${w}_sha${hash}"
            parmset="sha${hash}/${h}/${w}"
            cp lipsum lipsum_"$keyname"_mt 
            cp lipsum lipsum_"$keyname"_st
#            gprofng collect app -O ./MT/mt_genkey_"$keyname".er .././demo genkey "$keyname"_mt "$parmset" >> "$logfile" 2>&1
#            gprofng collect app -O ./MT/mt_sign_"$keyname".er .././demo sign "$keyname"_mt lipsum_"$keyname"_mt >> "$logfile" 2>&1
#            gprofng collect app -O ./MT/mt_verify_"$keyname".er .././demo verify "$keyname"_mt lipsum_"$keyname"_mt >> "$logfile" 2>&1
            perf stat -o "${keyname}_gk_res_mt.txt" ./demo genkey "$keyname"_mt "$parmset" >> "$logfile" 2>&1
            perf stat -o "${keyname}_sg_res_mt.txt" ./demo sign "$keyname"_mt lipsum_"$keyname"_mt >> "$logfile" 2>&1
            perf stat -o "${keyname}_vf_res_mt.txt" ./demo verify "$keyname"_mt lipsum_"$keyname"_mt >> "$logfile" 2>&1

#            gprofng collect app -O ./ST/st_genkey_"$keyname".er .././demo_st genkey "$keyname"_st "$parmset" >> "$logfile" 2>&1
#            gprofng collect app -O ./ST/st_sign_"$keyname".er .././demo_st sign "$keyname"_st lipsum_"$keyname"_st >> "$logfile" 2>&1
#            gprofng collect app -O ./ST/st_verify_"$keyname".er .././demo_st verify "$keyname"_st lipsum_"$keyname"_st >> "$logfile" 2>&1
            perf stat -o "${keyname}_gk_res_st.txt" ./demo_st genkey "$keyname"_st "$parmset" >> "$logfile" 2>&1
            perf stat -o "${keyname}_sg_res_st.txt" ./demo_st sign "$keyname"_st lipsum_"$keyname"_st >> "$logfile" 2>&1
            perf stat -o "${keyname}_vf_res_st.txt" ./demo_st verify "$keyname"_st lipsum_"$keyname"_st >> "$logfile" 2>&1

            rm "$keyname"_mt.* "$keyname"_st.* lipsum_"$keyname"_*
        done
    done
done