#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TMP_ROOT=${TMPDIR:-/tmp}
TMP_DIR=$(mktemp -d "$TMP_ROOT/msgex-roundtrip.XXXXXX")

cleanup() {
	if [ "${KEEP_ROUNDTRIP_TMP:-0}" != "1" ]; then
		rm -rf "$TMP_DIR"
	else
		printf 'Keeping temp dir: %s\n' "$TMP_DIR"
	fi
}
trap cleanup EXIT

require_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf 'Missing required command: %s\n' "$1" >&2
		exit 1
	fi
}

count_records() {
	awk '/^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9] /{count++} END{print count + 0}' "$1"
}

detect_uid() {
	awk '
		/^用户[:：]/ {
			value = $0
			sub(/^用户[:：]/, "", value)
			sub(/\(.*/, "", value)
			print value
			exit
		}
	' "$1"
}

to_utf8() {
	local input=$1
	local output=$2

	if iconv -f UTF-8 -t UTF-8 "$input" > "$output" 2>/dev/null; then
		return
	fi
	iconv -f GB18030 -t UTF-8 "$input" > "$output"
}

run_one() {
	local input=$1
	local index=$2
	local case_dir original_utf8 qq_uid first_dir second_dir first_db second_db first_txt second_txt
	local original_count first_count second_count

	if [ ! -f "$input" ]; then
		printf 'Input file not found: %s\n' "$input" >&2
		exit 1
	fi

	case_dir="$TMP_DIR/case-$index"
	original_utf8="$case_dir/original.utf8.txt"
	first_dir="$case_dir/first"
	second_dir="$case_dir/second"
	first_db="$first_dir/MsgEx.db"
	second_db="$second_dir/MsgEx.db"

	mkdir -p "$first_dir" "$second_dir"
	to_utf8 "$input" "$original_utf8"

	qq_uid=$(detect_uid "$original_utf8")
	if [ -z "$qq_uid" ]; then
		printf 'Could not detect QQ number from input: %s\n' "$input" >&2
		exit 1
	fi

	first_txt="$first_dir/$qq_uid.txt"
	second_txt="$second_dir/$qq_uid.txt"

	"$QQMSG" --import "$original_utf8" "$qq_uid" "$first_db" >/dev/null
	(cd "$first_dir" && SOURCE_DATE_EPOCH=$FIXED_EPOCH "$QQMSG" MsgEx.db "$qq_uid" >/dev/null)

	"$QQMSG" --import "$first_txt" "$qq_uid" "$second_db" >/dev/null
	(cd "$second_dir" && SOURCE_DATE_EPOCH=$FIXED_EPOCH "$QQMSG" MsgEx.db "$qq_uid" >/dev/null)

	original_count=$(count_records "$original_utf8")
	first_count=$(count_records "$first_txt")
	second_count=$(count_records "$second_txt")

	if [ "$original_count" -ne "$first_count" ] || [ "$original_count" -ne "$second_count" ]; then
		printf 'Record count mismatch for %s: original=%s first=%s second=%s\n' "$input" "$original_count" "$first_count" "$second_count" >&2
		exit 1
	fi

	if ! cmp -s "$first_txt" "$second_txt"; then
		printf 'Round-trip text mismatch for %s: %s differs from %s\n' "$input" "$first_txt" "$second_txt" >&2
		exit 1
	fi

	printf 'Round-trip OK: %s: %s records, exported texts are identical.\n' "$input" "$original_count"
}

require_cmd awk
require_cmd cmp
require_cmd iconv
require_cmd make
require_cmd mktemp

make -C "$SCRIPT_DIR" >/dev/null

QQMSG="$SCRIPT_DIR/qqmsg"
FIXED_EPOCH=0
INPUTS=("$@")

if [ "${#INPUTS[@]}" -eq 0 ]; then
	INPUTS=("$SCRIPT_DIR/QQ聊天记录030901.txt")
fi

for i in "${!INPUTS[@]}"; do
	run_one "${INPUTS[$i]}" "$i"
done

printf 'All round-trip tests passed: %s file(s).\n' "${#INPUTS[@]}"
