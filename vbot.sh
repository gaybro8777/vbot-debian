#!/bin/bash
cd vbot.debian/bin/Debug
mono vbot.debian.exe ${@:1}
cd ../../../
