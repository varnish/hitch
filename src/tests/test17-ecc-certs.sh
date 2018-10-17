#!/bin/sh
# Test loading an ECC certificate

. hitch_test.sh

start_hitch \
	--backend='[hitch-tls.org]:80' \
	--frontend="[localhost]:$LISTENPORT" \
	"${CERTSDIR}/ecc.example.com.pem"

s_client >s_client.dump
subj_name_eq "ecc.example.com" s_client.dump
curl_hitch
