#!/usr/bin/env bash

# Quick smoke test that exercises data moving across rproxy.
# Expected to be run at root of rproxy install tree.

DOCOLOR=0
USAGE="Usage: `basename $0` [-c]"

# Parse command line options.
while getopts hc OPT; do
    case "$OPT" in
        h)
            echo $USAGE
            exit 0
            ;;
        c)
            DOCOLOR=1
            ;;
    esac
done

if [ ${DOCOLOR} -eq 1 ]
then
  txtred=$(tput setaf 1)    # Red
  txtgrn=$(tput setaf 2)    # Green
  txtylw=$(tput setaf 3)	# Yellow
  txtrst=$(tput sgr0)       # Text reset
fi

SUCCESS="${txtgrn}[SUCCESS]${txtrst}"
FAILURE="${txtred}[FAILURE]${txtrst}"
WARNING="${txtylw}[WARNING]${txtrst}"

export BASE=`pwd`
export TEMP=`mktemp -d smoke.XXXX`

# See if we have curl
CURL=`command -v curl`

if [ "$CURL" = "" ]
then
	echo "curl not found, exiting..."
	exit 1
fi

export success=0
export failure=0
export warning=0

echo "------------- Initializing"
echo "Creating temporary directory ${TEMP}."

function checkcode {
    echo "Checking http code $1"
    if [ $? -eq 0 ] && [ "${code}" = "$1" ] 
    then
        success=`expr $success + 1`
        echo "${SUCCESS}"
    else
        failure=`expr $failure + 1`
        echo "${FAILURE}"
    fi
}

function checkresult {
    echo "Checking http code $1 with regex '$2'"
    export data=`cat ${TEMP}/curl.out`
		echo $data
    if [ $? -eq 0 ] && [ "${code}" = "$1" ] && [[ "${data}" =~ ${2} ]] 
    then
        success=`expr $success + 1`
        echo "${SUCCESS}"
    else
        failure=`expr $failure + 1`
        echo "${FAILURE}"
    fi
    rm ${TEMP}/curl.out
}

# Start the backend server
${BASE}/test/smoke/smoke_downstream &
sleep 1

# Start rproxy
${BASE}/src/rproxy ${BASE}/test/smoke/smoke_cfg.cfg &
sleep 1

export RP_HOST=localhost
export RP_PORT_1=8081
export RP_PORT_2=8082
export RP_PORT_3=8083
export RP_PORT_4=8084


echo ""
echo "------------- TEST 1: Testing simple GET on downstream."
export code=`${CURL} -w "%{http_code}\n" -s -o /dev/null -X GET "http://${RP_HOST}:${RP_PORT_1}/simple/"`
checkcode 200

echo ""
echo "------------- TEST 2: Testing simple POST on downstream."
export code=`${CURL} -w "%{http_code}\n" -s -o /dev/null -X POST "http://${RP_HOST}:${RP_PORT_1}/simple/"`
checkcode 200

echo ""
echo "------------- TEST 3: Testing simple PUT on downstream."
export code=`${CURL} -w "%{http_code}\n" -s -o /dev/null -X PUT -T ./test/smoke/smoke.sh "http://${RP_HOST}:${RP_PORT_1}/simple/"`
checkcode 200

echo ""
echo "------------- TEST 4: Testing simple DELETE on downstream."
export code=`${CURL} -w "%{http_code}\n" -s -o /dev/null -X DELETE "http://${RP_HOST}:${RP_PORT_1}/simple/"`
checkcode 200

echo ""
echo "------------- TEST 5: Testing busy on downstream."
export code=`${CURL} -w "%{http_code}\n" -s -o /dev/null -X GET "http://${RP_HOST}:${RP_PORT_1}/busy/"`
checkcode 503

echo ""
echo "------------- TEST 6: Testing not found on downstream."
export code=`${CURL} -w "%{http_code}\n" -s -o /dev/null -X GET "http://${RP_HOST}:${RP_PORT_1}/notfound/"`
checkcode 404

echo ""
echo "------------- TEST 7: Testing non-recognized uri (not configured in rproxy)."
export code=`${CURL} -w "%{http_code}\n" -s -o /dev/null -X GET "http://${RP_HOST}:${RP_PORT_1}/nonexistent/"`
checkcode 404

echo ""
echo "------------- TEST 8: Testing rewritten uri on downstream"
export code=`${CURL} -w "%{http_code}\n" -s -o /dev/null -X GET "http://${RP_HOST}:${RP_PORT_1}/rewritten/"`
checkcode 200

echo ""
echo "------------- TEST 9: Testing rewritten uri with bad downstream uri."
export code=`${CURL} -w "%{http_code}\n" -s -o /dev/null -X GET "http://${RP_HOST}:${RP_PORT_1}/badrewrite/"`
checkcode 404

echo ""
echo "------------- TEST 10: Testing GET with data on downstream."
export code=`${CURL} -w "%{http_code}\n" -s -o ${TEMP}/curl.out -X GET "http://${RP_HOST}:${RP_PORT_1}/data/"`
checkresult 200 'SUCCESS'

echo ""
echo "------------- TEST 11: Testing x-forwarded-for header."
export code=`${CURL} -w "%{http_code}\n" -s -o ${TEMP}/curl.out -X GET "http://${RP_HOST}:${RP_PORT_1}/forwarded/"`
checkresult 200 '127.0.0.1'

echo ""
echo "------------- TEST 12: Testing simple SSL enabled GET on downstream (Server-side SSL)."
export code=`${CURL} -w "%{http_code}\n" -k -s -o ${TEMP}/curl.out -X GET "https://${RP_HOST}:${RP_PORT_2}/simple/"`
checkcode 200

echo ""
echo "------------- TEST 13: Testing simple SSL enabled GET on downstream (Two-way SSL)."
export code=`${CURL} -w "%{http_code}\n" -k -s -o ${TEMP}/curl.out --key ${BASE}/test/smoke/client.key --cert ${BASE}/test/smoke/client.crt -X GET "https://${RP_HOST}:${RP_PORT_3}/simple/"`
checkcode 200

echo ""
echo "------------- TEST 14: Testing x-ssl-subject header."
export code=`${CURL} -w "%{http_code}\n" -k -s -o ${TEMP}/curl.out --key ${BASE}/test/smoke/client.key --cert ${BASE}/test/smoke/client.crt -X GET "https://${RP_HOST}:${RP_PORT_3}/subject/"`
checkresult 200 '/CN=Client'

echo ""
echo "------------- TEST 15: Testing x-ssl-issuer header."
export code=`${CURL} -w "%{http_code}\n" -k -s -o ${TEMP}/curl.out --key ${BASE}/test/smoke/client.key --cert ${BASE}/test/smoke/client.crt -X GET "https://${RP_HOST}:${RP_PORT_3}/issuer/"`
checkresult 200 '/CN=CA'

echo ""
echo "------------- TEST 16: Testing x-ssl-notbefore header."
export code=`${CURL} -w "%{http_code}\n" -k -s -o ${TEMP}/curl.out --key ${BASE}/test/smoke/client.key --cert ${BASE}/test/smoke/client.crt -X GET "https://${RP_HOST}:${RP_PORT_3}/notbefore/"`
checkresult 200 'Feb  4 16:52:42 2012 GMT'

echo ""
echo "------------- TEST 17: Testing x-ssl-notafter header."
export code=`${CURL} -w "%{http_code}\n" -k -s -o ${TEMP}/curl.out --key ${BASE}/test/smoke/client.key --cert ${BASE}/test/smoke/client.crt -X GET "https://${RP_HOST}:${RP_PORT_3}/notafter/"`
checkresult 200 'Feb  1 16:52:42 2022 GMT'

echo ""
echo "------------- TEST 18: Testing x-ssl-serial header."
export code=`${CURL} -w "%{http_code}\n" -k -s -o ${TEMP}/curl.out --key ${BASE}/test/smoke/client.key --cert ${BASE}/test/smoke/client.crt -X GET "https://${RP_HOST}:${RP_PORT_3}/serial/"`
checkresult 200 '01'

echo ""
echo "------------- TEST 19: Testing x-ssl-cipher header."
export code=`${CURL} -w "%{http_code}\n" -k -s -o ${TEMP}/curl.out --key ${BASE}/test/smoke/client.key --cert ${BASE}/test/smoke/client.crt -X GET "https://${RP_HOST}:${RP_PORT_3}/cipher/"`
checkresult 200 'RC4-SHA'

echo ""
echo "------------- TEST 20: Testing x-ssl-certificate header."
echo "SKIPPED: Enable when evhtp supports parsing multi-line headers."
echo ${WARNING}
warning=`expr $warning + 1`
# export code=`${CURL} -w "%{http_code}\n" -k -s -o ${TEMP}/curl.out --key ${BASE}/test/rproxy/client.key --cert ${BASE}/test/rproxy/client.crt -X GET "https://${RP_HOST}:${RP_PORT_3}/certificate/"`
# checkresult 200 ''

echo ""
echo "------------- TEST 21: Testing user-agent header."
export code=`${CURL} -w "%{http_code}\n" -k -s -o ${TEMP}/curl.out --key ${BASE}/test/smoke/client.key --cert ${BASE}/test/smoke/client.crt -X GET "https://${RP_HOST}:${RP_PORT_3}/useragent/"`
checkresult 200 "^curl.*"

echo ""
echo "------------- TEST 22: Testing host header."
export code=`${CURL} -w "%{http_code}\n" -k -s -o ${TEMP}/curl.out --key ${BASE}/test/smoke/client.key --cert ${BASE}/test/smoke/client.crt -X GET "https://${RP_HOST}:${RP_PORT_3}/host/"`
checkresult 200 "${RP_HOST}:${RP_PORT_3}"

echo ""
echo "------------- TEST 23: Testing accept header."
export code=`${CURL} -w "%{http_code}\n" -k -s -o ${TEMP}/curl.out --key ${BASE}/test/smoke/client.key --cert ${BASE}/test/smoke/client.crt -H "Accept: text/plain" -X GET "https://${RP_HOST}:${RP_PORT_3}/accept/"`
checkresult 200 'text/plain'

echo ""
echo "------------- TEST 24: Testing x509 extension header."
export code=`${CURL} -w "%{http_code}\n" -k -s -o ${TEMP}/curl.out --key ${BASE}/test/smoke/client.key --cert ${BASE}/test/smoke/client.crt -X GET "https://${RP_HOST}:${RP_PORT_3}/extension/"`
checkresult 200 'PUT_TEXT_HERE'

echo ""
echo "------------- TEST 25: Testing a slow backend connection."
export code=`${CURL} -w "%{http_code}\n" -s -o ${TEMP}/curl.out -X GET "http://${RP_HOST}:${RP_PORT_1}/slowdata/"`
checkresult 200 "0000000000"

echo ""
echo "------------- TEST 26: Testing a slow backend connection (SSL)."
export code=`${CURL} -w "%{http_code}\n" -k -s -o ${TEMP}/curl.out --key ${BASE}/test/smoke/client.key --cert ${BASE}/test/smoke/client.crt -X GET "https://${RP_HOST}:${RP_PORT_3}/slowdata/"`
checkresult 200 "0000000000"

echo ""
echo "------------- TEST 27: Testing an invalid chunk length."
export code=`${CURL} -w "%{http_code}\n" -s -o ${TEMP}/curl.out -X GET "http://${RP_HOST}:${RP_PORT_1}/badchunklength/"`
checkresult 200 "SUCCESS"

echo ""
echo "------------- TEST 28: Testing an invalid chunk response (SSL)."
export code=`${CURL} -w "%{http_code}\n" -k -s -o ${TEMP}/curl.out --key ${BASE}/test/smoke/client.key --cert ${BASE}/test/smoke/client.crt -X GET "https://${RP_HOST}:${RP_PORT_3}/badchunklength/"`
checkresult 200 "SUCCESS"

echo ""
echo "------------- TEST 29: Testing an invalid chunk transfer."
export code=`${CURL} -w "%{http_code}\n" -s -o ${TEMP}/curl.out -X GET "http://${RP_HOST}:${RP_PORT_1}/badchunktransfer/"`
checkresult 200 "DATA"

echo ""
echo "------------- TEST 30: Testing an invalid chunk transfer (SSL)."
export code=`${CURL} -w "%{http_code}\n" -k -s -o ${TEMP}/curl.out --key ${BASE}/test/smoke/client.key --cert ${BASE}/test/smoke/client.crt -X GET "https://${RP_HOST}:${RP_PORT_3}/badchunktransfer/"`
checkresult 200 "DATA"

echo ""
echo "------------- TEST 30: testing round-robin based load balancing."
echo "Making 8 requests, which should result in 4 responses downstream 1, and 4 responses from downstream 2"
for i in {1..8}; do
  ${CURL} -s -X GET http://${RP_HOST}:${RP_PORT_4}/test_rr/ >> ${TEMP}/rr.out
done

one_count=`grep one ${TEMP}/rr.out | wc -l`
two_count=`grep two ${TEMP}/rr.out | wc -l`
echo "Downstream 1 count: ${one_count}, Downstream 2 count: ${two_count}"

if [ "${one_count}" -eq 4 ] && [ "${two_count}" -eq 4 ] 
then
  success=`expr $success + 1`
  echo "${SUCCESS}"
else
  failure=`expr $failure + 1`
  echo "${FAILURE}"
fi

echo ""
echo "------------- Killing spawned processes."
for job in `jobs -p`
do
    kill $job 
done

echo ""
echo "------------- SUMMARY"
echo "${txtgrn}Success: ${success}${txtrst}"
echo "${txtred}Failure: ${failure}${txtrst}"
echo "${txtylw}Warning: ${warning}${txtrst}"

exit ${failure}
