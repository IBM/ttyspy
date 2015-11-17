#!/bin/sh -x

./session_receiver -ca ../../test_data/ca.pem -cert ../../test_data/cert.pem -key ../../test_data/cert.key -store /tmp/transcripts
