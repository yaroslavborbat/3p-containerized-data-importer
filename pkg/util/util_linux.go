package util

import (
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

// PunchHole attempts to zero a range in a file with fallocate, for block devices and pre-allocated files.
func PunchHole(outFile *os.File, start, length int64) error {
	klog.Infof("Punching %d-byte hole at offset %d", length, start)
	flags := uint32(unix.FALLOC_FL_PUNCH_HOLE | unix.FALLOC_FL_KEEP_SIZE)
	err := syscall.Fallocate(int(outFile.Fd()), flags, start, length)
	if err == nil {
		_, err = outFile.Seek(length, io.SeekCurrent) // Just to move current file position
	}
	return err
}