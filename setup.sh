#!/bin/bash
if [ ! -d "webapp" ]; then
  echo "ERROR: This script should be launched in the project directory."
  exit 1
  fi
if [  -f "webapp/app.db" ]; then
  echo "ERROR: The Database has already been created, remove app.db if you want to reset the instance."
  exit 1
  fi

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
key=`head -c32 /dev/urandom | base64`
csrf=`head -c32 /dev/urandom | base64`
salt=`head -c32 /dev/urandom | base64`
cd webapp
flask fab create-admin --username Admin --firstname Admin --lastname Admin --email PlumAdmin@changeme.xxx --password $key
cd ..
echo ""
echo configured with username admin
echo and password: $key
echo change your password and email in the web interface.
echo ""
echo To test in a non production environnement you may launch by running:
echo    source .venv/bin/activate
echo    cd webapp
echo    python ./run.py
echo
echo then navigate to http://127.0.0.1:5000/targetsview/list/
