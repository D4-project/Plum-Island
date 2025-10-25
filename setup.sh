#!/bin/bash
CONFIG_FILE="config.py"
echo "P.L.U.M. by C.I.R.C.L"
echo "Installation Starting... "
if [ ! -d "webapp" ]; then
  echo "ERROR: This script should be launched in the project directory."
  exit 1
  fi
if [  -f "webapp/app.db" ]; then
  echo "ERROR: The Database has already been created, remove app.db if you want to reset the instance."
  exit 1
  fi
if [  -f "webapp/$CONFIG_FILE" ]; then
  echo "ERROR: The Application has already been configured, remove or edit config.py to change configuration."
  exit 1
  fi

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
key=`head -c32 /dev/urandom | base64`
csrf=`head -c32 /dev/urandom | base64`
cd webapp
cp config.py.template config.py
CONFIG_FILE="config.py"
while true; do
    echo "-------------------------"
    echo "Basic Configuration:"
    read -p "KVROCKS Host Instance : " REDIS_HOST
    read -p "KVROCKS Port : " REDIS_PORT
    read -p "Meili Database Host Instance : " MEILI_HOST
    read -p "Meili Database Port : " MEILI_PORT
    read -p "Meili Database Password : " MEILI_PASSWORD
    echo "-------------------------"
    echo "KvRocsk Configuration : $REDIS_HOST:$REDIS_PORT"
    echo "Meili Configuration : http://$MEILI_HOST:$MEILI_PORT using $MEILI_PASSWORD"
    echo "You may change all this configuration later in config.py"
    echo "-------------------------"

    read -p "Are the parameters correct ? (y/n) : " CONFIRM

    if [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]]; then
        sed -i "s/^KVROCKS_HOST *= *.*/KVROCKS_HOST = \"$REDIS_HOST\"/" "$CONFIG_FILE"
        sed -i "s/^KVROCKS_PORT *= *.*/KVROCKS_PORT = $REDIS_PORT/" "$CONFIG_FILE"
        sed -i "s/^MEILI_KEY *= *.*/MEILI_KEY = \"$MEILI_PASSWORD\"/" "$CONFIG_FILE"
        sed -i "s/^MEILI_DATABASE_URI *= *.*/MEILI_DATABASE_URI = \"http:\/\/$MEILI_HOST:$MEILI_PORT\"/" "$CONFIG_FILE"
        sed -i "s/^SECRET_KEY *= *.*/SECRET_KEY = \"$csrf\"/" "$CONFIG_FILE"
        break
    else
        echo "Start over configuration..."
    fi
done

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
echo Then navigate to http://127.0.0.1:5000/targetsview/list/
