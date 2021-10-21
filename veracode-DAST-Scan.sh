#/bin/bash

        #$1 DAST_SCAN_NAME
        #$2 APP_URL

        echo ''
        echo '====== DEBUG START ======'
        echo '[INFO] DAST-Scan-Name: ' $1
        echo '[INFO] App-URL: ' $2
        echo '====== DEBUG END ======'
        echo ''

        echo '[INFO] ------------------------------------------------------------------------'
        echo '[INFO] --- CREATING JSON FILE...'
        echo '[INFO] ------------------------------------------------------------------------'
        echo  '{' >> da_scan.json
        echo  '  "name": "'$1'",' >> da_scan.json
        echo  '  "scans": [' >> da_scan.json
        echo  '    {' >> da_scan.json
        echo  '      "scan_config_request": {' >> da_scan.json
        echo  '        "target_url": {' >> da_scan.json
        echo  '          "url": "'$2'"' >> da_scan.json
        echo  '        }' >> da_scan.json
        echo  '      }' >> da_scan.json
        echo  '    }' >> da_scan.json
        echo  '  ],' >> da_scan.json
        echo  '  "schedule": {' >> da_scan.json
        echo  '    "duration": {' >> da_scan.json
        echo  '      "length": 1,' >> da_scan.json
        echo  '      "unit": "DAY"' >> da_scan.json
        echo  '    },' >> da_scan.json
        echo  '    "scheduled": true,' >> da_scan.json
        echo  '    "now": true' >> da_scan.json
        echo  '  }' >> da_scan.json
        echo  '}' >> da_scan.json
        echo ''

        #Launch DAST Scan by Using APIs
        echo '[INFO] ------------------------------------------------------------------------'
        echo '[INFO] LAUNCHING DAST SCAN '$1
        echo '[INFO] ------------------------------------------------------------------------'
        http --auth-type=veracode_hmac "https://api.veracode.com/was/configservice/v1/analyses" < da_scan.json || echo "[ERROR] There was a problem launching the DAST Scan..." | exit 1
        echo '[INFO] Scan launched successfully!'
        echo '[INFO] ------------------------------------------------------------------------'
        
