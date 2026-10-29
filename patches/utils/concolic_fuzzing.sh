#!/bin/bash
echo "================================================="
echo "AFL+QEMU and SymQEMU for concolic fuzzing script"
echo "================================================="


echo "[*] Performing basic sanity checks..."

if [ ! "`uname -s`" = "Linux" ]; then

  echo "[-] Error: concolic fuzzing is supported only on Linux."
  exit 1

fi


if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <AFL Path> <triforce-qemu Path> <SymQEMU Path>"
    exit 1
fi

AFL_FOLDER="$1"
TRIFORCE_QEMU_FOLDER="$2"
SYMQEMU_FOLDER="$3"

echo "[*] ----------------------Path Configuration --------------------------------------"
echo "[*] AFL: $1"
echo "[*] triforce-qemu: $2"
echo "[*] SYMQEMU: $3"
echo "[*] ----------------------Path Configuration --------------------------------------"
echo ""


if [ ! -f "${AFL_FOLDER}/afl-showmap" ]; then

  echo "[-] Error: ${AFL_FOLDER}/afl-showmap not found - compile AFL first!"
  exit 1

fi

if [ ! -f "${TRIFORCE_QEMU_FOLDER}/build/qemu-system-arm" ]; then

  echo "[-] Error: ${TRIFORCE_QEMU_FOLDER}/build/qemu-system-arm not found - compile triforce-qemu first!"
  exit 1

fi


if [ ! -f "${SYMQEMU_FOLDER}/build/qemu-system-arm" ]; then

  echo "[-] Error: ${SYMQEMU_FOLDER}/build/qemu-system-arm not found - compile symqemu first!"
  exit 1

fi

echo "[*] Testing SymQEMU ...."

SYMQEMU_TEST="/tmp/test-symqemu"

if [ ! -d "${SYMQEMU_TEST}" ]; then
	mkdir "${SYMQEMU_TEST}"
else
	rm "${SYMQEMU_TEST}"/*
fi

echo "12345678" > "${SYMQEMU_TEST}"/input1

SYMCC_OUTPUT_DIR="/tmp/output/" SYMCC_MEMORY_INPUT="1" "${SYMQEMU_FOLDER}/build/qemu-system-arm" -M concolic_replay -display none -replayConf "${SYMQEMU_FOLDER}/fw-example/replay.json" -D "${SYMQEMU_FOLDER}/build/qemu.log" -d concolic_replay -kernel "${SYMQEMU_FOLDER}/fw-example/stm32h7s78-dk.elf" -replayFile "${SYMQEMU_TEST}"/input1

if [ "$(ls -1 /tmp/output | wc -l)" -gt 0 ]; then
	echo "[+] SymQEMU test passed"
else
	echo "[+] SymQEMU test failed"
fi

if [ -d "${AFL_FOLDER}/input" ]; then
        rm -rf "${AFL_FOLDER}/input/*"
fi

mkdir -p "${AFL_FOLDER}/input"
echo "12345678" > "${AFL_FOLDER}/input"/input1


echo "[*] Clean AFL environment ..."
AFL_OUTPUT_FOLDER="${AFL_FOLDER}/output/fuzzer01/queue"

if [ -d "${AFL_OUTPUT_FOLDER}" ]; then
	rm -rf "${AFL_OUTPUT_FOLDER}"/*
fi

echo "[*] Start AFL for fuzz testing ..."

#"${AFL_FOLDER}/afl-fuzz" -i "${AFL_FOLDER}/input" -o "${AFL_FOLDER}/output" -t 2000 -M fuzzer01 -F sync_outdir -- "${TRIFORCE_QEMU_FOLDER}/build/qemu-system-arm" -M rehost-fuzzing -display none -kernel "${TRIFORCE_QEMU_FOLDER}/patches/fw-example/stm32h7s78-dk.elf" -aflConf "${TRIFORCE_QEMU_FOLDER}/patches/aflConfiguration.json" -aflFile @@ &>/dev/null &


echo "[*] Start SymQEMU for concolic fuzzing ..."

while true; do
	if [ ! -d "${AFL_OUTPUT_FOLDER}" ]; then
		echo "[-] afl output folder does not exist! Sleep for 10s"
		sleep 10
	else
		break
	fi
done 

echo "[*] AFL output folder: ${AFL_OUTPUT_FOLDER}"

echo "[*] Wait until there are enough test case in the queue ..."

while true; do
	if [ "$(ls -1 "$AFL_OUTPUT_FOLDER" | wc -l)" -lt 50 ]; then
		echo "[-] Less than 50 test cases in the queue..."
		sleep 10
	else
		break
	fi
done

prev_hash=""

sync_outdir="${AFL_OUTPUT_FOLDER}/../sync_outdir"
cmin_outdir="${AFL_OUTPUT_FOLDER}/../cmin_outdir"
tmp_outdir="${AFL_OUTPUT_FOLDER}/../outdir"

mkdir -p "${AFL_OUTPUT_FOLDER}/../symqemu-testcases"
mkdir -p "${sync_outdir}"
mkdir -p "${tmp_outdir}"
mkdir -p "${cmin_outdir}"


if [ -d "${sync_outdir}" ]; then
	echo "[*] Cleaning sync outdir...."
	rm -rf "${sync_outdir}"/*
fi

cnt=0

while true; do
	cur_hash=$(find "$AFL_OUTPUT_FOLDER" -type f -print0 | xargs -0 sha1sum | sha1sum | awk '{print $1}')
	
	echo "[*] cur cov = ${cur_hash}"
       	
	if [[ "$prev_hash" != "$cur_hash" ]]; then
		echo "[+] There is an update on cov. Run concolic fuzzing one time"
		
		rm -f "${AFL_OUTPUT_FOLDER}/../symqemu-testcases"/* 
		
		# afl-cmin test cases in the queue to avoid too much overhead on constraint solving in SymQEMU
		"${AFL_FOLDER}/afl-cmin" -i "${AFL_OUTPUT_FOLDER}" -o "${AFL_OUTPUT_FOLDER}/../symqemu-testcases" -t 2000 -- "${TRIFORCE_QEMU_FOLDER}/build/qemu-system-arm" -M rehost-fuzzing -display none -kernel "${TRIFORCE_QEMU_FOLDER}/patches/fw-example/stm32h7s78-dk.elf" -aflConf "${TRIFORCE_QEMU_FOLDER}/patches/aflConfiguration.json" -aflFile @@

		for cur_input in "${AFL_OUTPUT_FOLDER}/../symqemu-testcases"/*; do
			rm -f "${tmp_outdir}"/*
			
			rm -f "${cmin_outdir}"/*
			
			echo "[*] cur input: $cur_input"
		
			SYMCC_OUTPUT_DIR="${tmp_outdir}" SYMCC_MEMORY_INPUT="1" timeout 20s "${SYMQEMU_FOLDER}/build/qemu-system-arm" -M concolic_replay -display none -replayConf "${TRIFORCE_QEMU_FOLDER}/patches/aflConfiguration.json" -kernel "${TRIFORCE_QEMU_FOLDER}/patches/fw-example/stm32h7s78-dk.elf" -replayFile "${cur_input}"
			
			if [ $? -eq 124 ]; then
				echo "[-] file:${cur_input} timed out after 20s, giving up this case and exiting for inspectin"
				exit 1;
			fi


			# echo "[*] cmin all generated test cases and copy to a sync out dir"	

			# afl-cmin test cases generated by symqemu...	
			#if [ "$(ls -1 "$tmp_outdir" | wc -l)" -ne 0 ]; then
			#	echo "[*] afl-cmin testcases generated by symqemu ...."
			#	"${AFL_FOLDER}/afl-cmin" -i "${tmp_outdir}" -o "${cmin_outdir}" -t 2000 -- "${TRIFORCE_QEMU_FOLDER}/build/qemu-system-arm" -M rehost-fuzzing -display none -kernel "${TRIFORCE_QEMU_FOLDER}/patches/fw-example/stm32h7s78-dk.elf" -aflConf "${TRIFORCE_QEMU_FOLDER}/patches/aflConfiguration.json" -aflFile @@
			#else
			#	continue
			#fi

			for tmp_f in "${tmp_outdir}"/*; do
				if [ -f "$tmp_f" ]; then
					echo "[*] Moving ${tmp_f}.... to ${sync_outdir}/id:${cnt}"
					mv -- "$tmp_f" "${sync_outdir}/id:${cnt}"
					((cnt++))
				fi
			done
			echo "[+] Done copy. Sleep 120s"
		done

		prev_hash=${cur_hash}
	fi
	sleep 120
	
	#ccmin sync dir
	if [ "$(ls -1 "$sync_outdir" | wc -l)" -gt 5000 ]; then
		echo "[*] num of testcases is more then 5000, afl-cmin sync out dir ...."
		rm -f  "${cmin_outdir}"/*
		"${AFL_FOLDER}/afl-cmin" -i "${sync_outdir}" -o "${cmin_outdir}" -t 2000 -- "${TRIFORCE_QEMU_FOLDER}/build/qemu-system-arm" -M rehost-fuzzing -display none -kernel "${TRIFORCE_QEMU_FOLDER}/patches/fw-example/stm32h7s78-dk.elf" -aflConf "${TRIFORCE_QEMU_FOLDER}/patches/aflConfiguration.json" -aflFile @@
	
		rm -f "${sync_outdir}"/*
        	mv "${cmin_outdir}"/* "${sync_outdir}"/
	fi

done

echo "[-] should not be running here"


