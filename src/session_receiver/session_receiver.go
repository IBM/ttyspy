package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

type SessionLog struct {
	s        int
	username string
	gecos    string
}

func transcriptHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, "Unhandled method", 404)
	}

	username := req.Header.Get("X-Username")
	hostname := req.Header.Get("X-Hostname")
	gecos := req.Header.Get("X-Gecos")
	ssh_client := req.Header.Get("X-Ssh-Client")

	if req.Header.Get("Content-Type") != "application/typescript" {
		http.Error(w, "Unexpected content-type", 499)
	}
	if hostname == "" {
		http.Error(w, "Expected X-Hostname", 499)
	}
	if username == "" {
		http.Error(w, "Expected X-Username", 499)
	}
	if gecos == "" {
		http.Error(w, "Expected X-Gecos", 499)
	}

	dir := username + "/" + hostname
	start_timestamp := time.Now().UTC().Format(time.RFC3339)
	prefix := "transcript_" + start_timestamp + "_"
	os.MkdirAll(dir, 0755)
	file, err := ioutil.TempFile(dir, prefix)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	fmt.Fprintln(file, "Username:", username)
	fmt.Fprintln(file, "GECOS:", gecos)
	fmt.Fprintln(file, "Hostname:", hostname)
	fmt.Fprintln(file, "Session started:", start_timestamp)
	if ssh_client != "" {
		fmt.Fprintln(file, "SSH_Client:", ssh_client)
	}
	fmt.Fprintln(file, "")
	fmt.Fprintln(file, "")

	buf := make([]byte, 4096)
	for {
		n, err := req.Body.Read(buf)
		if err != nil && err != io.EOF {
			panic(err)
		}
		if n == 0 {
			break
		}

		if _, err := file.Write(buf[:n]); err != nil {
			panic(err)
		}
	}

	completion_timestamp := time.Now().UTC().Format(time.RFC3339)
	fmt.Fprintln(file, "")
	fmt.Fprintln(file, "")
	fmt.Fprintln(file, "Session ended:", completion_timestamp)
}

func handler(w http.ResponseWriter, req *http.Request) {
	fmt.Printf("Request %s\n", req.Method)
	for key, value := range req.Header {
		fmt.Printf("%s:\t%s\n", key, strings.Join(value, ", "))
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("This is an example server.\n"))
}

func main() {
	http.HandleFunc("/", handler)
	http.HandleFunc("/transcript", transcriptHandler)

	client_ca_pool := x509.NewCertPool()
	data, err := ioutil.ReadFile("ca.pem")
	if err == nil {
		client_ca_pool.AppendCertsFromPEM(data)
	}

	server := &http.Server{
		Addr: ":8090",
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  client_ca_pool,
		},
	}

	server.ListenAndServeTLS("cert.pem", "cert.key")
}
