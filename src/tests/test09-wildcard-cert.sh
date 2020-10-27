#!/bin/sh

. hitch_test.sh
set -x
start_hitch \
	--backend='[hitch-tls.org]:80' \
	--frontend="[localhost]:$LISTENPORT" \
	"${CERTSDIR}/wildcard.example.com" \
	"${CERTSDIR}/default.example.com"

s_client -servername foo.example.com >s_client.dump
subject_field_eq CN "*.example.com" s_client.dump
