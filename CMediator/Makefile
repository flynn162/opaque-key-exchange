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

test: default
	@set -euo pipefail
	echo '[make $@]'
	_isTerminal='0'
	_batchArgs=''
	if [ -t 0 ] && [ -t 1 ]; then _isTerminal='1'; fi
	if [ "$$_isTerminal" -eq 0 ]; then _batchArgs+=' --batch'; fi
	if [ "$$_isTerminal" -eq 0 ]; then echo "- Starting GDB in batch mode"; fi
	gdb -return-child-result -q $$_batchArgs -ex='r' -ex='bt full' -ex='q' --args ./build/test_libCMediator

sanitize: default
	@set -euo pipefail
	echo '[make $@]'
	./build/sanitize_libCMediator

clean:
	@set -euo pipefail
	echo '[make $@]'
	rm -vf  build/*.d  build/*.o  build/lib*.so  build/lib*.so.*  build/sanitize_lib*  build/test_lib*
	[ "$$(ls -A build/)" ] && echo "- Build directory is not empty" || (env TZ=UTC ls -laR --time-style=iso build/ ; echo "- Done")

clean_logs:
	@set -euo pipefail
	echo '[make $@]'
	rm -vf  build/*.log  build/.ninja_log
	[ "$$(ls -A build/)" ] && echo "- Build directory is not empty" || (env TZ=UTC ls -laR --time-style=iso build/ ; echo "- Done")


.PHONY: default verbose test sanitize clean clean_logs
