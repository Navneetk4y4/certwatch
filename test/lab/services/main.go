// Command labsvc is the lab's two instrumented endpoints, in one binary so the
// lab needs one image rather than two.
//
//	-mode=imds     item 067. A cloud metadata decoy. It records every inbound
//	               connection to a file the test asserts is EMPTY. Scenario S14
//	               passes only if this file has zero entries: the point is not
//	               that the decoy refused, it is that nothing ever knocked.
//
//	-mode=ingest   item 069. A fake control-plane ingest endpoint that captures
//	               FULL request bodies AND headers. Headers matter as much as
//	               bodies: a private key leaking through an Authorization
//	               header or a debug header is still a leak, and the canary
//	               must be able to scan both.
//
// Neither mode is part of the shipped product. Neither is imported by it.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

type record struct {
	At         time.Time           `json:"at"`
	RemoteAddr string              `json:"remote_addr"`
	Method     string              `json:"method,omitempty"`
	Path       string              `json:"path,omitempty"`
	Headers    map[string][]string `json:"headers,omitempty"`
	Body       string              `json:"body,omitempty"`
	BodyBytes  int                 `json:"body_bytes,omitempty"`
}

type recorder struct {
	mu   sync.Mutex
	path string
}

func (r *recorder) write(rec record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("record: %v", err)
		return
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(rec); err != nil {
		log.Printf("encode: %v", err)
	}
}

func main() {
	mode := flag.String("mode", "ingest", "imds or ingest")
	addr := flag.String("addr", ":80", "listen address")
	out := flag.String("out", "/data/record.jsonl", "JSONL record file")
	flag.Parse()

	rec := &recorder{path: *out}
	// Truncate at start so a record file is always this run's evidence and
	// never a leftover that makes a clean run look dirty, or vice versa.
	if f, err := os.Create(*out); err == nil {
		f.Close()
	}

	switch *mode {
	case "imds":
		// Record at the TCP layer, before any HTTP parsing. A scanner that
		// opens a connection and sends nothing has still touched the metadata
		// service, and that must show up.
		ln, err := net.Listen("tcp", *addr)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("imds-decoy listening on %s, recording to %s", *addr, *out)
		for {
			c, err := ln.Accept()
			if err != nil {
				log.Printf("accept: %v", err)
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				rec.write(record{At: time.Now().UTC(), RemoteAddr: c.RemoteAddr().String()})
				log.Printf("DECOY TOUCHED by %s", c.RemoteAddr())
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 512)
				n, _ := c.Read(buf)
				// Answer like the real thing would, so a scanner that IS
				// broken gets far enough to prove it.
				if n > 0 {
					fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 21\r\n\r\n"+
						"lab-decoy-credentials")
				}
			}(c)
		}

	case "ingest":
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
			body, _ := io.ReadAll(io.LimitReader(req.Body, 32<<20))
			rec.write(record{
				At: time.Now().UTC(), RemoteAddr: req.RemoteAddr,
				Method: req.Method, Path: req.URL.Path,
				Headers: req.Header, Body: string(body), BodyBytes: len(body),
			})
			w.WriteHeader(http.StatusAccepted)
			fmt.Fprintln(w, `{"accepted":true}`)
		})
		log.Printf("ingest listening on %s, capturing headers+bodies to %s", *addr, *out)
		srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		log.Fatal(srv.ListenAndServe())

	default:
		log.Fatalf("unknown -mode %q", *mode)
	}
}
