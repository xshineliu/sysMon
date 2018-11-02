#/bin/bash

MAXKEEP=30
PREFIX=/var/log/sar
TZOFF=8
interval=10

mkdir -p $PREFIX

loop() {

	ts=$(TZ='Asia/Shanghai' date +%Y%m%d)
	ts_last_day=$(TZ='Asia/Shanghai' date +%Y%m%d -d @$(( $(date +%s) - 86400)) )
	ts_to_del=$(TZ='Asia/Shanghai' date +%Y%m%d -d @$(( $(date +%s) - $((86400 * ${MAXKEEP} )) )) )
	FILENAME=${PREFIX}/sar.${ts}.log
	FILENAME_LASTDAY=${PREFIX}/sar.${ts_last_day}.log
	FILE_TO_DEL=${PREFIX}/sar.${ts_to_del}.log.gz


	if [[ -e ${FILENAME_LASTDAY} ]]; then
		if [[ ! -e ${FILENAME_LASTDAY}.gz ]]; then
			gzip ${FILENAME_LASTDAY} &
		fi
	fi

	if [[ -e ${FILE_TO_DEL} ]]; then
		rm -f ${FILE_TO_DEL} &
	fi



	now=$(date +%s)
	remain_sec=$(( 86400 - $(( $((now + $((TZOFF * 3600)))) % 86400)) ))

	sar -A ${interval} $(( $(($remain_sec + $interval)) % $interval)) >> ${FILENAME}

}


while [ 1 -gt 0 ]; do
	loop
done
