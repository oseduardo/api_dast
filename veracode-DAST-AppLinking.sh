#/bin/bash

        #$1 VID
        #$2 VKEY
        #$3 DAST_SCAN_NAME
        #$4 APP_NAME

        echo ''
        echo '====== DEBUG START ======'
        echo '[INFO] API-ID: ' $1
        echo '[INFO] API-Key: ' $2
        echo '[INFO] DAST-Scan-Name: ' $3
        echo '[INFO] App-Profile-Name: ' $4
        echo '====== DEBUG END ======'
        echo ''

        #Getting UUID of the App Profile to be linked to the DAST Scan
        echo '[INFO] ------------------------------------------------------------------------'
        echo '[INFO] GETTING APP PROFILE INFORMATION'
        echo '[INFO] ------------------------------------------------------------------------'
        echo ''
        http --auth-type=veracode_hmac "https://api.veracode.com/was/configservice/v1/platform_applications" --ignore-stdin -d -o platform_applications.json || echo "[ERROR] There was a problem retrieving Application Profile Info..." | exit 1
        echo '[INFO] Downloading App Profile Information...'
        if [ ! -f "platform_applications.json" ]; then
          echo '[ERROR] There are no App Profiles for your Organization'
          echo '[INFO] ------------------------------------------------------------------------'
          exit 1
        fi
        appProfiles=$(jq '._embedded.platform_applications' platform_applications.json)
        appProfileUUID=""
        for k in $(jq '. | keys | .[]' <<< $appProfiles); do
          arrValue=$(jq -r ".[$k]" <<< $appProfiles);
          strAppName=$(jq -r '.name' <<< "$arrValue");
          if [[ "$strAppName" == "$4" ]]; then
               appProfileUUID=$(jq -r '.uuid' <<< "$arrValue");
          fi               
        done
        if [ -z "$appProfileUUID" ];
        then
          echo '[ERROR] There is no an Application Profile with the name '$4
          exit 1
        else
          echo ''
          echo '[INFO] ------------------------------------------------------------------------'
          echo '[INFO] App-Profile-UUID: ' $appProfileUUID
          echo '[INFO] ------------------------------------------------------------------------'
          echo ''
        fi

        #Getting DAST Analysis ID
        echo ''
        echo '[INFO] ------------------------------------------------------------------------'
        echo '[INFO] GETTING DAST ANALYSIS ID'
        echo '[INFO] ------------------------------------------------------------------------'
        echo ''
        http --auth-type=veracode_hmac "https://api.veracode.com/was/configservice/v1/analyses?name=$3" --ignore-stdin -d -o analyses.json || echo "[ERROR] There was a problem retrieving DAST Analysis ID..." | exit 1
        echo '[INFO] Downloading Analyses Information...'
        if [ ! -f "analyses.json" ]; then
          echo '[ERROR] There are no Analysis information for DAST Scan '$3
          echo '[INFO] ------------------------------------------------------------------------'
          exit 1
        fi
        dastAnalysisInfo=$(jq '._embedded.analyses' analyses.json)
        dastAnalysisId=""
        for k in $(jq '. | keys | .[]' <<< $dastAnalysisInfo); do
          arrValue=$(jq -r ".[$k]" <<< $dastAnalysisInfo);
          dastAnalysisId=$(jq -r '.analysis_id' <<< "$arrValue");
        done
        echo ''
        echo '[INFO] ------------------------------------------------------------------------'
        echo '[INFO] DAST Scan - Analysis ID: '$dastAnalysisId
        echo '[INFO] ------------------------------------------------------------------------'
        echo ''

        #Getting DAST Scan ID
        echo ''
        echo '[INFO] ------------------------------------------------------------------------'
        echo '[INFO] GETTING DAST SCAN ID'
        echo '[INFO] ------------------------------------------------------------------------'
        echo ''
#        dastScanInfo=$(http --auth-type=veracode_hmac "https://api.veracode.com/was/configservice/v1/analyses/"$dastAnalysisId"/scans" | jq '._embedded.scans') || echo "[ERROR] There was a problem retrieving DAST Scan ID..." | exit 1
        http --auth-type=veracode_hmac "https://api.veracode.com/was/configservice/v1/analyses/"$dastAnalysisId"/scans" --ignore-stdin -d -o scan_information.json || echo "[ERROR] There was a problem retrieving DAST Scan ID..." | exit 1
        echo '[INFO] Downloading Scan Information...'
        if [ ! -f "scan_information.json" ]; then
          echo '[ERROR] There are no Scan information for DAST Scan '$3
          echo '[INFO] ------------------------------------------------------------------------'
          exit 1
        fi
        dastScanInfo=$(jq '._embedded.scans' scan_information.json)
        dastScanId=""
        for k in $(jq '. | keys | .[]' <<< $dastScanInfo); do
          arrValue=$(jq -r ".[$k]" <<< $dastScanInfo);
          dastScanId=$(jq -r '.scan_id' <<< "$arrValue");
        done
        echo ''
        echo '[INFO] ------------------------------------------------------------------------'
        echo '[INFO] DAST Scan - Scan ID: '$dastScanId
        echo '[INFO] ------------------------------------------------------------------------'
        echo ''

        echo '[INFO] ------------------------------------------------------------------------'
        echo '[INFO] --- CREATING JSON FILE WITH PAYLOAD...'
        echo '[INFO] ------------------------------------------------------------------------'
        echo  '{' >> applinking.json
        echo  '  "linked_platform_app_uuid": "'$appProfileUUID'"' >> applinking.json
        echo  '}' >> applinking.json

        #Linking DAST Scan to App Profile
        echo ''
        echo '[INFO] ------------------------------------------------------------------------'
        echo '[INFO] LINKING DAST SCAN '$3' WITH APPLICATION PROFILE '$4
        http --auth-type=veracode_hmac PUT "https://api.veracode.com/was/configservice/v1/scans/"$dastScanId"?method=PATCH" < applinking.json
        STATUS=${?}
        if [ $STATUS -gt 0 ];
        then
          echo '[ERROR] There was a problem linking the scan with the App Profile...'
          exit 1
        else
          echo '[INFO] App Linking was successful!'
          echo '[INFO] ------------------------------------------------------------------------'
        fi
