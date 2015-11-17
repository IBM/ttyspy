package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

var transcriptDir string = "/srv/transcripts"

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

	ts := time.Now().UTC()
	dir := fmt.Sprintf("%v/%v/%v/%04d/%02d/%02d", transcriptDir, username, hostname, ts.Year(), ts.Month(), ts.Day())
	start_timestamp := ts.Format(time.RFC3339)
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
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("This is an example server.\n"))
}

func main() {
	portPtr := flag.Int("port", 8090, "TCP port to listen on")
	clientCaFilePtr := flag.String("ca", "", "TLS CA used to authenticate clients")
	serverCertFilePtr := flag.String("cert", "", "TLS certificate to use for server")
	serverKeyFilePtr := flag.String("key", "", "TLS private key to use for server")
	transcriptStoreDirPtr := flag.String("store", "/srv/transcripts", "Directory to store transcripts")

	flag.Parse()

	if *serverKeyFilePtr == "" {
		*serverKeyFilePtr = *serverCertFilePtr
	}

	if *clientCaFilePtr == "" || *serverCertFilePtr == "" || *serverKeyFilePtr == "" {
		flag.PrintDefaults()
		return
	}

	transcriptDir = *transcriptStoreDirPtr

	http.HandleFunc("/", handler)
	http.HandleFunc("/transcript", transcriptHandler)

	client_ca_pool := x509.NewCertPool()
	data, err := ioutil.ReadFile(*clientCaFilePtr)
	if err == nil {
		client_ca_pool.AppendCertsFromPEM(data)
	}

	address := fmt.Sprintf(":%v", *portPtr)
	fmt.Println("Listening on " + address)
	server := &http.Server{
		Addr: address,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  client_ca_pool,
		},
	}

	err = server.ListenAndServeTLS(*serverCertFilePtr, *serverKeyFilePtr)
	if err != nil {
		panic(err)
	}
}
