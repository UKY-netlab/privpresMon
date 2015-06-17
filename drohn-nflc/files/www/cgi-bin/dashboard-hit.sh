#!/bin/bash

hc_dir="drohn_vault_dir"
hc_file="dashboard_hit_count"
hc_file_tmp="dashboard_hit_count.tmp"

if [ -f ${hc_dir}${hc_file} ]; then
        hitcount=`cat ${hc_dir}${hc_file}`
else
        hitcount=0
fi
hitcount=$((hitcount + 1))
echo "$hitcount" > ${hc_dir}${hc_file_tmp}
mv ${hc_dir}${hc_file_tmp} ${hc_dir}${hc_file}
