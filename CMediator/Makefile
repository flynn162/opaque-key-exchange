.ONESHELL:
SHELL = /bin/bash

default:
	@set -euo pipefail
	echo '[make $@]'
	ninja

verbose:
	@set -euo pipefail
	echo '[make $@]'
	ninja -v

stat:
	@set -euo pipefail
	echo '[make $@]'
	TZ=UTC ls -laR --full-time build/
	echo -e "\n- sha256:"
	find build/ -type f -name '*' -print0 | sort -z | xargs -0 -r -n1 -- sha256sum --
	echo "- end sha256"

clean:
	@set -euo pipefail
	echo '[make $@]'
	rm -vf  build/*.o  build/lib*.so  build/lib*.so.*  build/sanitize_lib*  build/test_lib*
	[ "$$(ls -A build/)" ] && echo "- Build directory is not empty" || (env TZ=UTC ls -laR --time-style=iso build/ ; echo "- Done")

clean_logs:
	@set -euo pipefail
	echo '[make $@]'
	rm -vf  build/*.log  build/.ninja_log
	[ "$$(ls -A build/)" ] && echo "- Build directory is not empty" || (env TZ=UTC ls -laR --time-style=iso build/ ; echo "- Done")

.PHONY: default verbose clean clean_logs
