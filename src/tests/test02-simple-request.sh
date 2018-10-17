#!/bin/sh
#
# Test basic argument handling.
#
. hitch_test.sh

start_hitch \
	--backend="[hitch-tls.org]:80" \
	--frontend="[localhost]:$LISTENPORT" \
	"${CERTSDIR}/site1.example.com"

s_client >s_client.dump
subj_name_eq "site1.example.com" s_client.dump
curl_hitch
