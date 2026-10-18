#!/bin/sh
cd /d/anpu
UNFORMATTED=$(gofmt -l $(find . -name '*.go'))
printf 'UNFORMATTED_START\n%s\nUNFORMATTED_END\n' "$UNFORMATTED"