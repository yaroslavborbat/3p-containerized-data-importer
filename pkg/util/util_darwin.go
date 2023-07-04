package util

import (
	"os"
)

// PunchHole attempts to zero a range in a file with fallocate, for block devices and pre-allocated files.
func PunchHole(outFile *os.File, start, length int64) error {
	panic("not implemented")
	return nil
}