package main

import (
	"context"
	"flag"
	"os"

	"github.com/google/go-containerregistry/pkg/logs"
	"k8s.io/klog/v2"
)

func init() {
	klog.InitFlags(nil)
	flag.Parse()
}

func main() {
	ctx := context.Background()

	defer klog.Flush()

	logs.Progress.SetOutput(os.Stdout)
	logs.Warn.SetOutput(os.Stderr)

	klog.Infoln("Starting registry importer")

	importer := NewImporter()
	if err := importer.Run(ctx); err != nil {
		klog.Fatalf("Error running registry importer: %+v", err)
	}

	klog.Infoln("Finished running registry importer")
}
