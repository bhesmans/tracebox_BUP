#!/bin/bash

cd $(dirname $0)
for file in detect_*.py; do
	echo `date +%s`: Running ${file}
	python ${file} $@
	sleep 1
done