#!/bin/sh

set -x -e

cp -fv captive-portal.py /usr/local/sbin/captive-portal
cp -fv captive-portal@.service /lib/systemd/system/
pipenv install --system --deploy
