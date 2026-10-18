#!/bin/sh
cd /d/anpu/dist
tgz=$(ls anpu_*_linux_*.tar.gz anpu_*_darwin_*.tar.gz 2>/dev/null | wc -l)
zip=$(ls anpu_*_windows_*.zip 2>/dev/null | wc -l)
sbom=$(ls *.sbom.cyclonedx.json 2>/dev/null | wc -l)
echo "tar.gz=$tgz zip=$zip sbom=$sbom"
ls -1