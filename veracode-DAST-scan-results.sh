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
        echo '====== DEBUG END ======'
        echo ''

        SCAN_SLEEP_TIME=120

        #Getting GUID of the App Profile linked to the DAST Scan
        echo '[INFO] ------------------------------------------------------------------------'
        echo '[INFO] GETTING APP PROFILE INFORMATION'
        appProfiles=$(http --auth-type=veracode_hmac "https://api.veracode.com/appsec/v1/applications/?name="$4 | jq '._embedded.applications') || echo "[ERROR] There was a problem retrieving Application Profile Info..." | exit 1
        appProfileGUID=""
        for k in $(jq '. | keys | .[]' <<< $appProfiles); do
          arrValue=$(jq -r ".[$k]" <<< $appProfiles);
          strAppName=$(jq -r '.profile.name' <<< "$arrValue");
          if [[ "$strAppName" == "$4" ]]; then
               appProfileGUID=$(jq -r '.guid' <<< "$arrValue");
          fi               
        done
        if [ -z "$appProfileGUID" ];
        then
          echo '[ERROR] There is no an Application Profile with the name '$4
          exit 1
        else
          echo '[INFO] App-Profile-GUID: ' $appProfileGUID
          echo '[INFO] ------------------------------------------------------------------------'
          echo ''
        fi

        #Getting DAST Analysis ID
        echo ''
        echo '[INFO] ------------------------------------------------------------------------'
        echo '[INFO] GETTING DAST ANALYSIS ID'
        dastAnalysisId=""
        dastAnalysisInfo=$(http --auth-type=veracode_hmac "https://api.veracode.com/was/configservice/v1/analyses?name=$3" | jq '._embedded.analyses') || echo "[ERROR] There was a problem retrieving DAST Analysis ID..." | exit 1
        for k in $(jq '. | keys | .[]' <<< $dastAnalysisInfo); do
          arrValue=$(jq -r ".[$k]" <<< $dastAnalysisInfo);
          dastAnalysisId=$(jq -r '.analysis_id' <<< "$arrValue");
        done
        echo '[INFO] DAST Scan - Analysis ID: '$dastAnalysisId
        echo '[INFO] ------------------------------------------------------------------------'
        echo ''

        #Getting DAST Scan Information
        echo ''
        echo '[INFO] ------------------------------------------------------------------------'
        echo '[INFO] GETTING DAST SCAN INFORMATION'
        while true;
        do
          scanStatus=""
          dastScanInfo=$(http --auth-type=veracode_hmac "https://api.veracode.com/was/configservice/v1/analyses/"$dastAnalysisId"/scans" | jq '._embedded.scans') || echo "[ERROR] There was a problem retrieving DAST Scan ID..." | exit 1
          for k in $(jq '. | keys | .[]' <<< $dastScanInfo); do
            arrValue=$(jq -r ".[$k]" <<< $dastScanInfo);
            scanStatus=$(jq -r '.latest_occurrence_status.status_type' <<< "$arrValue");
          done

          if [[ $scanStatus = "FINISHED_RESULTS_AVAILABLE" ]];
          then
                echo '[INFO] Scan has finished...'
                echo '[INFO] ------------------------------------------------------------------------'
                echo ''
                echo ''
                echo '[INFO] ------------------------------------------------------------------------'
                echo '[INFO] GETTING DAST SUMMARY REPORT'
                strPolicyComplianceStatus=$(http --auth-type=veracode_hmac "https://api.veracode.com/appsec/v2/applications/"$appProfileGUID"/summary_report" | jq '.policy_compliance_status') || echo "[ERROR] There was a problem retrieving Policy Compliance Status..." | exit 1
                if [[ $strPolicyComplianceStatus = *"Did Not Pass"* ]];
                then
                  echo ''
                  echo '[INFO] Application: '$4' - DAST Scan Name: '$3' - Did NOT Pass'
                  summaryReport=$(http --auth-type=veracode_hmac "https://api.veracode.com/appsec/v2/applications/"$appProfileGUID"/summary_report" | jq '."dynamic-analysis".modules.module') || echo "[ERROR] There was a problem retrieving Summary Report..." | exit 1
                  for k in $(jq '. | keys | .[]' <<< $summaryReport); do
                    arrValue=$(jq -r ".[$k]" <<< $summaryReport);
                    numScore=$(jq -r '.score' <<< "$arrValue");
                    numFlawsSev5=$(jq -r '.numflawssev5' <<< "$arrValue");
                    numFlawsSev4=$(jq -r '.numflawssev4' <<< "$arrValue");
                    numFlawsSev3=$(jq -r '.numflawssev3' <<< "$arrValue");
                    numFlawsSev2=$(jq -r '.numflawssev2' <<< "$arrValue");
                    numFlawsSev1=$(jq -r '.numflawssev1' <<< "$arrValue");
                    echo ''
                    echo '[INFO] Final Score: '$numScore
                    echo '[INFO] Number of flaws - Very High Severity: '$numFlawsSev5
                    echo '[INFO] Number of flaws - High Severity: '$numFlawsSev4
                    echo '[INFO] Number of flaws - Medium Severity: '$numFlawsSev3
                    echo '[INFO] Number of flaws - Low Severity: '$numFlawsSev2
                    echo '[INFO] Number of flaws - Very Low Severity: '$numFlawsSev1
                  done
                else
                  echo ''
                  echo '[INFO] Application: '$4' - DAST Scan Name: '$3' - Did Pass'
                fi
                echo '[INFO] ------------------------------------------------------------------------'
                break;
          else
                echo '[INFO] Latest scan status: '$scanStatus
                echo '[INFO] Scan in process...'
                echo '[INFO] wait 2 more minutes ...'
                sleep $SCAN_SLEEP_TIME
          fi         
        done
