#/bin/bash

        #$1 VID
        #$2 VKEY

        echo ''
        echo '====== DEBUG START ======'
        echo '[INFO] API-ID: ' $1
        echo '[INFO] API-Key: ' $2
        echo '====== DEBUG END ======'
        echo ''

        #Create Credentials File
        echo '[INFO] ------------------------------------------------------------------------'
        echo '[INFO] --- CONFIGURING API CREDENTIALS FILE...'
        echo '[INFO] ------------------------------------------------------------------------'
        echo '[default]' >> credentials.txt
        echo 'veracode_api_key_id='$1 >> credentials.txt
        echo 'veracode_api_key_secret='$2 >> credentials.txt
        mkdir /home/vsts/.veracode/
        cp -f credentials.txt /home/vsts/.veracode/credentials
        chmod 755 /home/vsts/.veracode/credentials
        echo ''

        #Install Veracode Authentication Library
        echo '[INFO] ------------------------------------------------------------------------'
        echo '[INFO ] --- INSTALLING VERACODE AUTHENTICATION LIBRARY...'
        echo '[INFO] ------------------------------------------------------------------------'
        pip install veracode-api-signing || echo "[ERROR] There was a problem Installing Veracode Authentication Library..." | exit 1
        echo ''
