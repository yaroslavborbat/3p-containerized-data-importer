package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strconv"

	"github.com/djherbis/buffer"
	"github.com/djherbis/nio/v3"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/stream"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
	cdiv1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"
	"kubevirt.io/containerized-data-importer/pkg/common"
	cc "kubevirt.io/containerized-data-importer/pkg/controller/common"
	"kubevirt.io/containerized-data-importer/pkg/importer"
	"kubevirt.io/containerized-data-importer/pkg/util"
	prometheusutil "kubevirt.io/containerized-data-importer/pkg/util/prometheus"
)

// FIXME(ilya-lesikov): certdir

func NewImporter() *Importer {
	return &Importer{}
}

type Importer struct {
	src            string
	srcType        string
	srcContentType string
	srcUsername    string
	srcPassword    string
	srcInsecure    bool
	dest           string
	destUsername   string
	destPassword   string
	destInsecure   bool
	certDir        string
	sha256Sum      string
	md5Sum         string
}

func (i *Importer) Run(ctx context.Context) error {
	promCertsDir, err := os.MkdirTemp("", "certsdir")
	if err != nil {
		return fmt.Errorf("error creating prometheus certs directory: %w", err)
	}
	defer os.RemoveAll(promCertsDir)
	prometheusutil.StartPrometheusEndpoint(promCertsDir)

	if err := i.parseOptions(); err != nil {
		return fmt.Errorf("error parsing options: %w", err)
	}

	if i.srcType == cc.SourceRegistry {
		return i.runForRegistry(ctx)
	} else {
		return i.runForDataSource(ctx)
	}
}

func (i *Importer) parseOptions() error {
	i.src, _ = util.ParseEnvVar(common.ImporterEndpoint, false)
	i.srcType, _ = util.ParseEnvVar(common.ImporterSource, false)
	i.srcContentType, _ = util.ParseEnvVar(common.ImporterContentType, false)
	i.srcInsecure, _ = strconv.ParseBool(os.Getenv(common.InsecureTLSVar))
	i.dest, _ = util.ParseEnvVar(common.ImporterDestinationEndpoint, false)
	i.destInsecure, _ = strconv.ParseBool(os.Getenv(common.DestinationInsecureTLSVar))
	i.sha256Sum, _ = util.ParseEnvVar(common.ImporterSHA256Sum, false)
	i.md5Sum, _ = util.ParseEnvVar(common.ImporterMD5Sum, false)
	i.certDir, _ = util.ParseEnvVar(common.ImporterCertDirVar, false)

	i.srcUsername, _ = util.ParseEnvVar(common.ImporterAccessKeyID, false)
	i.srcPassword, _ = util.ParseEnvVar(common.ImporterSecretKey, false)
	if i.srcUsername == "" && i.srcPassword == "" && i.srcType == cc.SourceRegistry {
		srcAuthConfig, _ := util.ParseEnvVar(common.ImporterAuthConfig, false)
		if srcAuthConfig != "" {
			authFile, err := registryAuthFile(srcAuthConfig)
			if err != nil {
				return fmt.Errorf("error parsing source auth config: %w", err)
			}

			i.srcUsername, i.srcPassword, err = credsFromRegistryAuthFile(authFile, i.src)
			if err != nil {
				return fmt.Errorf("error getting creds from source auth config: %w", err)
			}
		}
	}

	i.destUsername, _ = util.ParseEnvVar(common.ImporterDestinationAccessKeyID, false)
	i.destPassword, _ = util.ParseEnvVar(common.ImporterDestinationSecretKey, false)
	if i.destUsername == "" && i.destPassword == "" {
		destAuthConfig, _ := util.ParseEnvVar(common.ImporterDestinationAuthConfig, false)
		if destAuthConfig != "" {
			authFile, err := registryAuthFile(destAuthConfig)
			if err != nil {
				return fmt.Errorf("error parsing destination auth config: %w", err)
			}

			i.destUsername, i.destPassword, err = credsFromRegistryAuthFile(authFile, i.dest)
			if err != nil {
				return fmt.Errorf("error getting creds from destination auth config: %w", err)
			}
		}
	}

	return nil
}

func (i *Importer) runForRegistry(ctx context.Context) error {
	destImageName := fmt.Sprintf("%s:latest", i.dest)
	srcNameOpts := i.srcNameOptions()
	srcRemoteOpts := i.srcRemoteOptions(ctx)
	destNameOpts := i.destNameOptions()
	destRemoteOpts := i.destRemoteOptions(ctx)

	srcRef, err := name.ParseReference(i.src, srcNameOpts...)
	if err != nil {
		return fmt.Errorf("error parsing source image name: %w", err)
	}

	srcDesc, err := remote.Get(srcRef, srcRemoteOpts...)
	if err != nil {
		return fmt.Errorf("error getting source image descriptor: %w", err)
	}

	srcImage, err := srcDesc.Image()
	if err != nil {
		return fmt.Errorf("error getting source image from descriptor: %w", err)
	}

	destRef, err := name.ParseReference(destImageName, destNameOpts...)
	if err != nil {
		return fmt.Errorf("error parsing destination image name: %w", err)
	}

	klog.Infof("Writing image %q to registry", destImageName)
	if err := remote.Write(destRef, srcImage, destRemoteOpts...); err != nil {
		return fmt.Errorf("error writing image to registry: %w", err)
	}

	klog.Infoln("Image upload completed")
	return nil
}

func (i *Importer) runForDataSource(ctx context.Context) error {
	ds, err := i.newDataSource(ctx)
	if err != nil {
		return fmt.Errorf("error creating data source: %w", err)
	}
	defer ds.Close()

	pipeReader, pipeWriter := nio.Pipe(buffer.New(64 * 1024 * 1024))

	errsGroup, ctx := errgroup.WithContext(ctx)
	errsGroup.Go(func() error {
		defer pipeWriter.Close()
		return i.streamDataSourceToArchive(ctx, ds, pipeWriter)
	})
	errsGroup.Go(func() error {
		defer pipeReader.Close()
		return i.uploadLayersAndImage(ctx, pipeReader)
	})

	return errsGroup.Wait()
}

func (i *Importer) newDataSource(ctx context.Context) (importer.DataSourceInterface, error) {
	var result importer.DataSourceInterface

	switch i.srcType {
	case cc.SourceHTTP:
		var err error
		result, err = importer.NewHTTPDataSource(i.src, i.srcUsername, i.srcPassword, i.certDir, cdiv1.DataVolumeContentType(i.srcContentType))
		if err != nil {
			return nil, fmt.Errorf("error creating HTTP data source: %w", err)
		}
	default:
		return nil, fmt.Errorf("unknown source type: %s", i.srcType)
	}

	return result, nil
}

func (i *Importer) streamDataSourceToArchive(ctx context.Context, ds importer.DataSourceInterface, pipeWriter *nio.PipeWriter) error {
	destFilename, err := ds.Filename()
	if err != nil {
		return fmt.Errorf("error getting destination filename: %w", err)
	}

	srcLength, err := ds.Length()
	if err != nil {
		return fmt.Errorf("error getting source length: %w", err)
	}

	tarWriter := tar.NewWriter(pipeWriter)
	defer tarWriter.Close()

	fileReader, err := ds.ReadCloser()
	if err != nil {
		return fmt.Errorf("error getting file reader: %w", err)
	}
	defer fileReader.Close()

	header := &tar.Header{
		Name:     path.Join("disk", destFilename),
		Size:     int64(srcLength),
		Mode:     0644,
		Typeflag: tar.TypeReg,
	}

	if err := tarWriter.WriteHeader(header); err != nil {
		return fmt.Errorf("error writing tar header: %w", err)
	}

	// Wrap data source reader with progress and speed metrics.
	instrumentedReader := NewProgressMeterReader(fileReader, uint64(srcLength))
	instrumentedReader.StartTimedUpdate()

	if i.sha256Sum != "" {
		hash := sha256.New()

		writer := io.MultiWriter(tarWriter, hash)
		klog.Infoln("Streaming source")
		if _, err := io.Copy(writer, instrumentedReader); err != nil {
			return fmt.Errorf("error copying file contents: %w", err)
		}
		klog.Infoln("Source streaming completed")

		sum := hex.EncodeToString(hash.Sum(nil))
		if sum != i.sha256Sum {
			return fmt.Errorf("sha256 sum mismatch: %s != %s", sum, i.sha256Sum)
		}
	} else if i.md5Sum != "" {
		hash := md5.New()

		writer := io.MultiWriter(tarWriter, hash)
		klog.Infoln("Streaming source")
		if _, err := io.Copy(writer, instrumentedReader); err != nil {
			return fmt.Errorf("error copying file contents: %w", err)
		}
		klog.Infoln("Source streaming completed")

		sum := hex.EncodeToString(hash.Sum(nil))
		if sum != i.md5Sum {
			return fmt.Errorf("md5 sum mismatch: %s != %s", sum, i.md5Sum)
		}
	} else {
		klog.Infoln("Streaming source")
		if _, err := io.Copy(tarWriter, instrumentedReader); err != nil {
			return fmt.Errorf("error copying file contents: %w", err)
		}
		klog.Infoln("Source streaming completed")
	}

	return nil
}

func (i *Importer) uploadLayersAndImage(ctx context.Context, pipeReader *nio.PipeReader) error {
	nameOpts := i.destNameOptions()
	remoteOpts := i.destRemoteOptions(ctx)
	imageName := fmt.Sprintf("%s:latest", i.dest)
	image := empty.Image

	ref, err := name.ParseReference(imageName, nameOpts...)
	if err != nil {
		return fmt.Errorf("error parsing image name: %w", err)
	}

	repo, err := name.NewRepository(i.dest, nameOpts...)
	if err != nil {
		return fmt.Errorf("error constructing new repository: %w", err)
	}

	layer := stream.NewLayer(pipeReader, stream.WithCompressionLevel(gzip.BestCompression))

	klog.Infoln("Uploading layer to registry")
	if err := remote.WriteLayer(repo, layer, remoteOpts...); err != nil {
		return fmt.Errorf("error uploading layer: %w", err)
	}
	klog.Infoln("Layer uploaded")

	image, err = mutate.AppendLayers(image, layer)
	if err != nil {
		return fmt.Errorf("error appending layer to image: %w", err)
	}

	klog.Infof("Uploading image %q to registry", imageName)
	if err := remote.Write(ref, image, remoteOpts...); err != nil {
		return fmt.Errorf("error uploading image: %w", err)
	}
	klog.Infoln("Image uploaded")

	return nil
}

func (i *Importer) srcNameOptions() []name.Option {
	nameOpts := []name.Option{}

	if i.srcInsecure {
		nameOpts = append(nameOpts, name.Insecure)
	}

	return nameOpts
}

func (i *Importer) destNameOptions() []name.Option {
	nameOpts := []name.Option{}

	if i.destInsecure {
		nameOpts = append(nameOpts, name.Insecure)
	}

	return nameOpts
}

func (i *Importer) srcRemoteOptions(ctx context.Context) []remote.Option {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: i.srcInsecure,
	}

	transport := &(*http.DefaultTransport.(*http.Transport))
	transport.TLSClientConfig = tlsConfig

	remoteOpts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithTransport(transport),
		remote.WithAuth(&authn.Basic{Username: i.srcUsername, Password: i.srcPassword}),
	}

	return remoteOpts
}

func (i *Importer) destRemoteOptions(ctx context.Context) []remote.Option {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: i.destInsecure,
	}

	transport := &(*http.DefaultTransport.(*http.Transport))
	transport.TLSClientConfig = tlsConfig

	remoteOpts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithTransport(transport),
		remote.WithAuth(&authn.Basic{Username: i.destUsername, Password: i.destPassword}),
	}

	return remoteOpts
}
