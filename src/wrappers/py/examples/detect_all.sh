#!/bin/bash

cd $(dirname $0)
for file in detect_*.py; do
	python ${file} $@
done