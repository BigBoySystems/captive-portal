#!/bin/sh

set -x -e

cp -fv captive-portal.py /usr/local/sbin/captive-portal
cp -fv captive-portal@.service /lib/systemd/system/
chmod 644 /lib/systemd/system/captive-portal@.service
pipenv install --system --deploy
