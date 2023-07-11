package main

import (
	"archive/tar"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/djherbis/buffer"
	"github.com/djherbis/nio/v3"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/stream"
	"golang.org/x/sync/errgroup"
	"io"
	"k8s.io/klog/v2"
	cdiv1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"
	"kubevirt.io/containerized-data-importer/pkg/common"
	cc "kubevirt.io/containerized-data-importer/pkg/controller/common"
	"kubevirt.io/containerized-data-importer/pkg/importer"
	"kubevirt.io/containerized-data-importer/pkg/util"
	prometheusutil "kubevirt.io/containerized-data-importer/pkg/util/prometheus"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
)

// FIXME(ilya-lesikov): certdir

const (
	imageLabelSourceImageSize        = "source-image-size"
	imageLabelSourceImageVirtualSize = "source-image-virtual-size"
	imageLabelSourceImageFormat      = "source-image-format"
)

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
	destImageName  string
	destUsername   string
	destPassword   string
	destInsecure   bool
	certDir        string
	sha256Sum      string
	md5Sum         string
}

type ImageInfo struct {
	VirtualSize int    `json:"virtual-size"`
	Format      string `json:"format"`
}

const (
	imageInfoSize        = 64 * 1024 * 1024
	pipeBufSize          = 64 * 1024 * 1024
	tempImageInfoPattern = "tempfile"
)

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
	i.destImageName, _ = util.ParseEnvVar(common.ImporterDestinationEndpoint, false)
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

			i.destUsername, i.destPassword, err = credsFromRegistryAuthFile(authFile, i.destImageName)
			if err != nil {
				return fmt.Errorf("error getting creds from destination auth config: %w", err)
			}
		}
	}

	return nil
}

func (i *Importer) runForRegistry(ctx context.Context) error {
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

	destRef, err := name.ParseReference(i.destImageName, destNameOpts...)
	if err != nil {
		return fmt.Errorf("error parsing destination image name: %w", err)
	}

	klog.Infof("Writing image %q to registry", i.destImageName)
	if err := remote.Write(destRef, srcImage, destRemoteOpts...); err != nil {
		return fmt.Errorf("error writing image to registry: %w", err)
	}

	klog.Infoln("Image upload completed")
	return nil
}

func (i *Importer) runForDataSource(ctx context.Context) error {
	var sourceImageFilename string
	var sourceImageSize int
	var sourceImageReader io.ReadCloser
	{
		ds, err := i.newDataSource(ctx)
		if err != nil {
			return fmt.Errorf("error creating data source: %w", err)
		}
		defer ds.Close()

		sourceImageFilename, err = ds.Filename()
		if err != nil {
			return fmt.Errorf("error getting source filename: %w", err)
		}

		sourceImageSize, err = ds.Length()
		if err != nil {
			return fmt.Errorf("error getting source image size: %w", err)
		}

		if sourceImageSize == 0 {
			return fmt.Errorf("zero data source image size")
		}

		sourceImageReader, err = ds.ReadCloser()
		if err != nil {
			return fmt.Errorf("error getting source image reader: %w", err)
		}
	}

	// Wrap data source reader with progress and speed metrics.
	progressMeterReader := NewProgressMeterReader(sourceImageReader, uint64(sourceImageSize))
	progressMeterReader.StartTimedUpdate()

	pipeReader, pipeWriter := nio.Pipe(buffer.New(pipeBufSize))
	imageInfoCh := make(chan ImageInfo)
	errsGroup, ctx := errgroup.WithContext(ctx)
	errsGroup.Go(func() error {
		return i.inspectAndStreamSourceImage(ctx, sourceImageFilename, sourceImageSize, progressMeterReader, pipeWriter, imageInfoCh)
	})
	errsGroup.Go(func() error {
		defer pipeReader.Close()
		return i.uploadLayersAndImage(ctx, pipeReader, sourceImageSize, imageInfoCh)
	})

	return errsGroup.Wait()
}

func (i *Importer) inspectAndStreamSourceImage(ctx context.Context, sourceImageFilename string, sourceImageSize int, sourceImageReader io.ReadCloser, pipeWriter *nio.PipeWriter, imageInfoCh chan ImageInfo) error {
	var tarWriter *tar.Writer
	{
		tarWriter = tar.NewWriter(pipeWriter)
		header := &tar.Header{
			Name:     path.Join("disk", sourceImageFilename),
			Size:     int64(sourceImageSize),
			Mode:     0644,
			Typeflag: tar.TypeReg,
		}

		if err := tarWriter.WriteHeader(header); err != nil {
			return fmt.Errorf("error writing tar header: %w", err)
		}
	}

	var checksumWriters []io.Writer
	var checksumCheckFuncList []func() error
	{
		if i.sha256Sum != "" {
			hash := sha256.New()
			checksumWriters = append(checksumWriters, hash)
			checksumCheckFuncList = append(checksumCheckFuncList, func() error {
				sum := hex.EncodeToString(hash.Sum(nil))
				if sum != i.sha256Sum {
					return fmt.Errorf("sha256 sum mismatch: %s != %s", sum, i.sha256Sum)
				}

				return nil
			})
		}

		if i.md5Sum != "" {
			hash := md5.New()
			checksumWriters = append(checksumWriters, hash)
			checksumCheckFuncList = append(checksumCheckFuncList, func() error {
				sum := hex.EncodeToString(hash.Sum(nil))
				if sum != i.md5Sum {
					return fmt.Errorf("md5 sum mismatch: %s != %s", sum, i.md5Sum)
				}

				return nil
			})
		}
	}

	var streamWriter io.Writer
	{
		writers := []io.Writer{tarWriter}
		writers = append(writers, checksumWriters...)
		streamWriter = io.MultiWriter(writers...)
	}

	errsGroup, ctx := errgroup.WithContext(ctx)

	imageInfoSourceReader, imageInfoSourceWriter := nio.Pipe(buffer.New(imageInfoSize))
	sourceReader := io.TeeReader(sourceImageReader, imageInfoSourceWriter)

	errsGroup.Go(func() error {
		defer tarWriter.Close()
		defer pipeWriter.Close()
		defer sourceImageReader.Close()
		defer imageInfoSourceWriter.Close()

		klog.Infoln("Streaming from the source")
		doneSize, err := io.Copy(streamWriter, sourceReader)
		if err != nil {
			return fmt.Errorf("error copying file contents: %w", err)
		}

		if doneSize != int64(sourceImageSize) {
			return fmt.Errorf("source image size mismatch: %d != %d", doneSize, sourceImageSize)
		}

		for _, checksumCheckFunc := range checksumCheckFuncList {
			if err = checksumCheckFunc(); err != nil {
				return err
			}
		}

		klog.Infoln("Source streaming completed")

		return nil
	})

	errsGroup.Go(func() error {
		defer imageInfoSourceReader.Close()

		info, err := getImageInfo(ctx, imageInfoSourceReader)
		if err != nil {
			return err
		}

		imageInfoCh <- info

		return nil
	})

	return errsGroup.Wait()
}

func (i *Importer) newDataSource(_ context.Context) (importer.DataSourceInterface, error) {
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

func (i *Importer) uploadLayersAndImage(ctx context.Context, pipeReader *nio.PipeReader, sourceImageSize int, ImageInfoCh chan ImageInfo) error {
	nameOpts := i.destNameOptions()
	remoteOpts := i.destRemoteOptions(ctx)
	image := empty.Image

	ref, err := name.ParseReference(i.destImageName, nameOpts...)
	if err != nil {
		return fmt.Errorf("error parsing image name: %w", err)
	}

	repo, err := name.NewRepository(ref.Context().Name(), nameOpts...)
	if err != nil {
		return fmt.Errorf("error constructing new repository: %w", err)
	}

	layer := stream.NewLayer(pipeReader)

	klog.Infoln("Uploading layer to registry")
	if err := remote.WriteLayer(repo, layer, remoteOpts...); err != nil {
		return fmt.Errorf("error uploading layer: %w", err)
	}
	klog.Infoln("Layer uploaded")

	imageInfo := <-ImageInfoCh

	cnf, err := image.ConfigFile()
	if err != nil {
		return fmt.Errorf("error getting image config: %w", err)
	}

	cnf.Config.Labels = map[string]string{}
	cnf.Config.Labels[imageLabelSourceImageVirtualSize] = fmt.Sprintf("%d", imageInfo.VirtualSize)
	cnf.Config.Labels[imageLabelSourceImageSize] = fmt.Sprintf("%d", sourceImageSize)
	cnf.Config.Labels[imageLabelSourceImageFormat] = imageInfo.Format

	image, err = mutate.ConfigFile(image, cnf)
	if err != nil {
		return fmt.Errorf("error mutating image config: %w", err)
	}

	image, err = mutate.AppendLayers(image, layer)
	if err != nil {
		return fmt.Errorf("error appending layer to image: %w", err)
	}

	klog.Infof("Uploading image %q to registry", i.destImageName)
	if err := remote.Write(ref, image, remoteOpts...); err != nil {
		return fmt.Errorf("error uploading image: %w", err)
	}

	if err := writeImportCompleteMessage(sourceImageSize, imageInfo.VirtualSize, imageInfo.Format); err != nil {
		return fmt.Errorf("error writing import complete message: %w", err)
	}

	return nil
}

func getImageInfo(ctx context.Context, sourceReader io.ReadCloser) (ImageInfo, error) {
	formatSourceReaders, err := importer.NewFormatReaders(sourceReader, 0)
	if err != nil {
		klog.Errorf("Error creating readers: %v", err)
		return ImageInfo{}, err
	}

	klog.Infoln("Creating temp image info file")
	tempImageInfoFile, err := os.CreateTemp("", tempImageInfoPattern)
	if err != nil {
		return ImageInfo{}, fmt.Errorf("error creating temp file: %w", err)
	}

	klog.Infoln("Write to temp image info file")
	uncompressedN, err := io.CopyN(tempImageInfoFile, formatSourceReaders.TopReader(), imageInfoSize)
	if err != nil {
		return ImageInfo{}, fmt.Errorf("error writing to temp file: %w", err)
	}

	if err = tempImageInfoFile.Close(); err != nil {
		return ImageInfo{}, fmt.Errorf("error closing temp file: %w", err)
	}

	cmd := exec.CommandContext(ctx, "qemu-img", "info", "--output=json", tempImageInfoFile.Name())
	outRaw, err := cmd.Output()
	if err != nil {
		return ImageInfo{}, fmt.Errorf("error running qemu-img info: %w", err)
	}

	var imageInfo ImageInfo
	if err = json.Unmarshal(outRaw, &imageInfo); err != nil {
		return ImageInfo{}, fmt.Errorf("error parsing qemu-img info output: %w", err)
	}

	if imageInfo.Format != "raw" {
		_, err = io.Copy(&EmptyWriter{}, formatSourceReaders.TopReader())
		if err != nil {
			return ImageInfo{}, fmt.Errorf("error writing to temp file: %w", err)
		}

		return imageInfo, nil
	}

	cmd = exec.CommandContext(ctx, "file", "-b", tempImageInfoFile.Name())
	outRaw, err = cmd.Output()
	if err != nil {
		return ImageInfo{}, fmt.Errorf("error running qemu-img info: %w", err)
	}

	out := string(outRaw)

	klog.Infoln("Parsing with file command output:", out)

	if strings.HasPrefix(out, "ISO") {
		imageInfo.Format = "iso"
	}

	n, err := io.Copy(&EmptyWriter{}, formatSourceReaders.TopReader())
	if err != nil {
		return ImageInfo{}, fmt.Errorf("error writing to temp file: %w", err)
	}

	uncompressedN += n

	imageInfo.VirtualSize = int(uncompressedN)

	return imageInfo, nil
}

type EmptyWriter struct{}

func (w EmptyWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func writeImportCompleteMessage(sourceImageSize, sourceImageVirtualSize int, sourceImageFormat string) error {
	rawMsg, err := json.Marshal(util.RegistryImporterInfo{
		SourceImageSize:        sourceImageSize,
		SourceImageVirtualSize: sourceImageVirtualSize,
		SourceImageFormat:      sourceImageFormat,
	})
	if err != nil {
		return err
	}

	message := string(rawMsg)

	err = util.WriteTerminationMessage(message)
	if err != nil {
		return err
	}

	klog.Infoln("Image uploaded: " + message)

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
