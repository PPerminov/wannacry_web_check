#!/bin/bash

if [[ $1 == 'setup' ]]
then
  pip install -r requirements.txt
fi

uwsgi --ini wannacry.ini
