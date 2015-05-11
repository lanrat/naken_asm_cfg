#! /usr/bin/env bash

mkdir -p out/svg/

rm out/svg/*.svg

dot -Tsvg out/*.dot -O 

mv out/*.svg out/svg/

echo "Done"
