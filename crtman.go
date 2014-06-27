package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"text/template"
	"time"
)

var (
	server    = flag.String("server", "", "Command")
	serverssl = flag.String("serverssl", "", "Command")
	html1     = `<!DOCTYPE html>
<html>
<head>
<link rel="stylesheet" href="https://code.jquery.com/ui/1.10.3/themes/smoothness/jquery-ui.css">
<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.9.1/jquery.min.js"></script>
<script src="https://code.jquery.com/ui/1.10.3/jquery-ui.min.js"></script>
<link href='https://fonts.googleapis.com/css?family=Lobster|Dosis|Montserrat' rel='stylesheet' type='text/css'>
<style>
body{
	font-family: Montserrat;
	padding:0;
	margin:0;
    background: #ff0;
}
button{
	font-family: Montserrat;
}
h1 {
	font-family: Lobster;
	background: rgb(43, 80, 226);
	color: white;
	margin: 0;
	padding: 30px;
}
h3{
	font-family: Dosis;
}
#calist{
	cursor: pointer;
	padding: 30px;
	border: 3px dotted #fff;
}
#certs div span {
	min-width: 200px;
	display: inline-block;
}
#certs div a {
	margin: 10px;
}
#caname1{
	font-family: Dosis;
}
#body {
   padding:10px 10px 120px 10px;
}
#footer{
	background: rgb(0, 0, 0);
	margin: 20px;
	padding: 30px;
}
footer{
	background: rgb(255, 0, 0);
	color: #fff;
	padding: 0;
    position:fixed;
    bottom:0;
    height: 80px;
    width: 100%;
}
footer a{
	font-family: Lobster;
	color: #fff;
}
#cert{
	display:none;
}
</style>
</head>
<body>
<script src="code.js">
</script>
<body>
	<h1>crtman - Certificate Manager</h1>
	<div id="body">
		<h2>CA List</h3>
		<div id="calist"></div>
		<input type='text' id='newca' placeholder='CA' /> <button id='btnCA'>Creat CA</button>
		<div id="cert">
			<h2>Certificates</h3>
			<div id="caname1">CA: <span id='caname' /></div>
			<div id="certs"></div>
			<input type='text' id='newcert' placeholder='Domain Name' /> <button id='btnCert'>Creat Certificate</button>
		</div>
	</div>
	<footer><div id="footer">&copy;<a href="https://github.com/CossackPyra/crtman">https://github.com/CossackPyra/crtman</a></div></footer>
</body>
</html>`
	code1 = `$(document).ready(function() {
	$("#btnCA").click(createCA)
	$("#btnCert").click(createCert)
	loadca();
});

function loadca() {
	$.ajax({
		url: "/listca",
		type: 'GET',
		timeout: 40000,
		processData: false,
		dataType: 'json',
		success: function(result) {
			var calist = $('#calist')
			calist.empty()
			for (var id in result) {
				var d1 = $('<div />')
				var s1 = result[id]
				d1.append($('<span />').text(s1)).click({
					s1: s1
				}, function(event) {
					loadcerts(event.data.s1)
				})
				calist.append(d1)
			}

		},
		fail: function(xhr, status, error) {
			report("Failed to query")
		}
	});
}

function report(x) {
	console.log(x);
}

function createCA() {
	console.log("newca 2")
	var ca = $('#newca').val()
	if (ca == "") return
	$('#newca').val('')
	var o1 = {
		ca: ca
	}


	$.ajax({
		url: "/newca",
		type: 'POST',
		timeout: 40000,
		contentType: 'application/json',
		data: JSON.stringify(o1),
		processData: false,
		dataType: 'json',
		success: function(result) {
			// report(result.text)
			console.log("newca ok", result)
			loadca()
		},
		fail: function(xhr, status, error) {
			console.log("newca false", status, error)
			report("Failed to query")
		}
	});

}
var selectedCA

function loadcerts(ca) {
	selectedCA = ca
	$('#caname').text(ca)
	$('#certs').empty()
	$('#cert').show()

	var o1 = {
		ca: ca
	}
	$.ajax({
		url: "/listcerts",
		type: 'POST',
		timeout: 40000,
		contentType: 'application/json',
		data: JSON.stringify(o1),
		processData: false,
		dataType: 'json',
		success: function(result) {
			var certs = $('#certs')
			certs.empty()
			for (var id in result) {
				var d1 = $('<div />')
				var s1 = id
				d1.append($('<span />').text(s1)).click({
					s1: s1
				}, function(event) {
					// alert(event.data.s1)
					// loadcerts(s1)
				})
				d1.append($('<a />', {
					href: "/ca/" + selectedCA + "/" + id + ".key",
					text: "key"
				}))
				d1.append($('<a />', {
					href: "/ca/" + selectedCA + "/" + id + ".crt",
					text: "crt"
				}))
				certs.append(d1)
			}

		},
		fail: function(xhr, status, error) {
			report("Failed to query")
		}
	});
}


function createCert(ca, domain) {
	var cert = $('#newcert').val()
	if (cert == "") return
	$('#newcert').val('')
	var o1 = {
		ca: selectedCA,
		domain: cert
	}


	$.ajax({
		url: "/newcert",
		type: 'POST',
		timeout: 40000,
		contentType: 'application/json',
		data: JSON.stringify(o1),
		processData: false,
		dataType: 'json',
		success: function(result) {
			// report(result.text)
			loadcerts(selectedCA)
		},
		fail: function(xhr, status, error) {
			report("Failed to query")
		}
	});

}`
)

func main() {
	os.Mkdir("ca", 0700)
	flag.Parse()

	var group sync.WaitGroup

	http.HandleFunc("/newcert", h_newcert)
	http.HandleFunc("/listcerts", h_listcerts)
	http.HandleFunc("/newca", h_newca)
	http.HandleFunc("/listca", h_listca)
	http.HandleFunc("/", h_index)
	http.HandleFunc("/code.js", h_code)

	// http.Handle("/w/", http.StripPrefix("/w/", http.FileServer(http.Dir("w"))))
	http.Handle("/ca/", http.StripPrefix("/ca/", http.FileServer(http.Dir("ca"))))

	if *serverssl != "" {
		println("Starting secure server")
		https1 := &http.Server{
			Addr:           *serverssl,
			Handler:        nil,
			ReadTimeout:    25 * time.Second,
			WriteTimeout:   25 * time.Second,
			MaxHeaderBytes: 1 << 15,
		}

		group.Add(1)
		go func() {
			fmt.Printf("Secure server: https://%s/\n", *serverssl)
			log.Fatal(https1.ListenAndServeTLS("etc/server.crt", "etc/server.key"))
			group.Done()
		}()
	} else {
		println("Starting insecure server")
		server1 := *server
		if server1 == "" {
			server1 = "127.0.0.1:8010"
		}
		http1 := &http.Server{
			Addr:           server1,
			Handler:        nil,
			ReadTimeout:    25 * time.Second,
			WriteTimeout:   25 * time.Second,
			MaxHeaderBytes: 1 << 15,
		}

		group.Add(1)
		go func() {
			fmt.Printf("Insecure server: http://%s/\n", server1)
			log.Fatal(http1.ListenAndServe())
			group.Done()
		}()

	}

	group.Wait()

}
func h_newca(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		b, e := ioutil.ReadAll(r.Body)
		if e != nil {
			fmt.Fprintf(w, `{ "error": true }`)
			return
		}
		//var json0 map[string]interface{}
		var m1 map[string]string
		e = json.Unmarshal(b, &m1)
		if e != nil {
			fmt.Fprintf(w, `{ "error": true }`)
			return
		}
		ca := m1["ca"]
		matched, e := regexp.MatchString("^[\\da-zA-Z]*$", ca)
		if !matched || e != nil {
			fmt.Fprintf(w, `{ "error": true }`)
			return
		}
		dir1 := "ca/" + ca
		os.Mkdir(dir1, 0700)
		dir2 := dir1 + "/"

		if myexec("ca genrsa", "openssl", "genrsa", "-out", dir2+"rootCA.key", "2048") {
			fmt.Fprintf(w, `{ "error": true }`)
			return
		}

		// if myexec("ca req", "openssl", "req", "-x509", "-new", "-key", dir2+"rootCA.key", "-days", "10000", "-out", dir2+"rootCA.crt", "-config", "ssl.cnf", "-batch") {
		if myexec("ca req", "openssl", "req", "-x509", "-new", "-key", dir2+"rootCA.key", "-days", "10000", "-out", dir2+"rootCA.crt", "-batch") {
			fmt.Fprintf(w, `{ "error": true }`)
			return
		}

		fmt.Fprintf(w, `{ "ok": true }`)

	}
}

func myexec(id string, args ...string) bool {
	b1, err := exec.Command(args[0], args[1:]...).Output()
	fmt.Println("myexec", id)
	var args1 []interface{}
	for _, s1 := range args {
		args1 = append(args1, s1)
	}
	fmt.Println(args1...)
	if err != nil {
		log.Println(id, string(b1), err)
		return true
	}
	return false
}

func h_listca(w http.ResponseWriter, r *http.Request) {
	files, _ := ioutil.ReadDir("ca")
	var files1 []string
	for _, f := range files {
		files1 = append(files1, f.Name())
	}
	b1, _ := json.Marshal(files1)
	w.Write(b1)
}

func h_listcerts(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		b, e := ioutil.ReadAll(r.Body)
		if e != nil {
			fmt.Fprintf(w, `{ "error": true }`)
			return
		}
		//var json0 map[string]interface{}
		var m1 map[string]string
		e = json.Unmarshal(b, &m1)
		if e != nil {
			fmt.Fprintf(w, `{ "error": true }`)
			return
		}
		ca := m1["ca"]
		matched, e := regexp.MatchString("^[\\da-zA-Z]*$", ca)
		if !matched || e != nil {
			fmt.Fprintf(w, `{ "error": true }`)
			return
		}
		dir1 := "ca/" + ca
		files, _ := ioutil.ReadDir(dir1)
		m2 := map[string]bool{}
		// var files1 []string
		for _, f := range files {
			name := f.Name()
			if strings.HasSuffix(name, ".key") {
				id := name[0 : len(name)-4]
				m2[id] = true
			}
			if strings.HasSuffix(name, ".crt") {
				id := name[0 : len(name)-4]
				m2[id] = true
			}
		}
		b1, _ := json.Marshal(m2)
		w.Write(b1)
	}
}

func h_newcert(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		b, e := ioutil.ReadAll(r.Body)
		if e != nil {
			fmt.Fprintf(w, `{ "error": true }`)
			return
		}
		//var json0 map[string]interface{}
		var m1 map[string]string
		e = json.Unmarshal(b, &m1)
		if e != nil {
			fmt.Fprintf(w, `{ "error": true }`)
			return
		}
		domain := m1["domain"]
		ca := m1["ca"]
		matched, e := regexp.MatchString("^[\\da-zA-Z]*$", ca)
		matched1, e1 := regexp.MatchString("^[\\da-zA-Z\\.]*$", domain)
		if !matched || !matched1 || e != nil || e1 != nil {
			fmt.Fprintf(w, `{ "error": true }`)
			return
		}
		dir1 := "ca/" + ca
		os.Mkdir(dir1, 0700)
		dir2 := dir1 + "/"

		templ1 := `
[ req ]
default_bits       = 4096
default_md         = sha512
default_keyfile    = key.pem
prompt             = no
encrypt_key        = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
CN={{ .Domain }}
`

		t1, err := template.New("Config").Parse(templ1)
		if err != nil {
			log.Println("failed to loaded template")
			fmt.Fprintf(w, `{ "error": true }`)
			return
		}

		var wr bytes.Buffer
		err = t1.Execute(&wr, struct{ Domain string }{domain})
		if err != nil {
			log.Println("failed to parse template")
			fmt.Fprintf(w, `{ "error": true }`)
			return
		}

		ioutil.WriteFile(dir2+domain+".cnf", wr.Bytes(), 0600)

		if myexec("d genrsa", "openssl", "genrsa", "-out", dir2+domain+".key", "2048") {
			fmt.Fprintf(w, `{ "error": true }`)
			return
		}

		if myexec("d csr", "openssl", "req", "-new", "-key", dir2+domain+".key", "-out", dir2+domain+".csr", "-config", dir2+domain+".cnf", "-batch") {
			fmt.Fprintf(w, `{ "error": true }`)
			return
		}

		if myexec("d crt", "openssl", "x509", "-req",
			"-in", dir2+domain+".csr",
			"-CA", dir2+"rootCA.crt",
			"-CAkey", dir2+"rootCA.key", "-CAcreateserial",
			"-out", dir2+domain+".crt", "-days", "5000") {
			fmt.Fprintf(w, `{ "error": true }`)
			return
		}

		fmt.Fprintf(w, `{ "ok": true }`)

	}
}
func h_index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, html1)
}
func h_code(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, code1)
}
