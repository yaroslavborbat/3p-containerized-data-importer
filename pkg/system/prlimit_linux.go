/*
Copyright 2018 The CDI Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package system

import (
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
)

func prlimit(pid int, limit int, value *syscall.Rlimit) error {
	_, _, e1 := syscall.RawSyscall6(syscall.SYS_PRLIMIT64, uintptr(pid), uintptr(limit), uintptr(unsafe.Pointer(value)), 0, 0, 0)
	if e1 != 0 {
		return errors.Wrapf(e1, "error setting prlimit on %d with value %d on pid %d", limit, value, pid)
	}
	return nil
}
