#!/bin/bash -e

$(dirname $0)/build/git-version-gen
autoreconf -fiv
