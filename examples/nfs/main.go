// Command nfs serves a directory over NFSv4.0. It shows the
// application-owned side of the split: the app binds the listener and decides
// who can reach it; the nfs4.Server only speaks the protocol. NFSv4 carries
// only AUTH_SYS identities, so expose the listener to trusted networks only.
//
// Mount from macOS:
//
//	sudo mount -t nfs -o vers=4.0,tcp,port=20490 localhost:/ /tmp/nfsmnt
//
// Mount from Linux:
//
//	mount -t nfs -o vers=4.0,port=20490 <host>:/ /mnt/x
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/nfs4"
)

func main() {
	address := flag.String("addr", "127.0.0.1:20490", "listen address")
	root := flag.String("root", ".", "directory to serve")
	flag.Parse()

	listener, err := net.Listen("tcp", *address)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server := &nfs4.Server{
		FileSystem: facetfs.Dir(*root),
		Logger:     func(err error) { log.Printf("connection: %v", err) },
	}
	log.Printf("serving %s at %s", *root, listener.Addr())
	if err := server.Serve(ctx, listener); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}
