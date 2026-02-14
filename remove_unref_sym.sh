#!/usr/bin/env bash

export CROSS_COMPILE=arm-linux-gnueabihf-

${CROSS_COMPILE}strip --strip-unneeded $1 && \
${CROSS_COMPILE}readelf -r -W $1 | awk 'NR>3' | awk '{print $5}'  | sort | uniq > ref.txt && \
${CROSS_COMPILE}readelf -s -W $1 | awk 'NR>3' |  awk '{print $8}'  | sort | uniq > syms.txt && \
diff ref.txt syms.txt | grep "^>" | grep -v "\$t" | grep -v "\$d" | awk '{print $2}' > unused.txt && \
llvm-objcopy --strip-symbols unused.txt $1;
rm -rf ref.txt syms.txt unused.txt
