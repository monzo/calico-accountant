package main

import (
	"flag"
	"os"

	"github.com/golang/glog"
	"github.com/monzo/calico-accountant/metrics"
	"github.com/monzo/calico-accountant/watch"
)

func main() {
	flag.Parse()

	port, ok := os.LookupEnv("METRICS_SERVER_PORT")
	if !ok {
		port = "9009"
	}

	cw, err := watch.New()
	if err != nil {
		glog.Fatalf("Error setting up calico watcher: %v", err)
	}

	metrics.Run(cw, port)
}
