//go:build windows
// +build windows

package utils

/*
Copyright 2018 Gravitational, Inc.

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

import (
	"os"
	"strings"

	"github.com/gravitational/trace"
)

const lockPostfix = ".lock.tmp"

// On Windows we use auxiliary .lock.tmp files to acquire locks, so we can still read/write target
// files themselves.
//
// .lock.tmp files are deliberately not cleaned up. Their presence doesn't matter to the actual
// locking. Repeatedly removing them on unlock when acquiring dozens of locks in a short timespan
// was causing flock.Flock.TryRLock to return either "access denied" or "The process cannot access
// the file because it is being used by another process".
func getPlatformLockFilePath(path string) string {
	// If target file is itself dedicated lockfile, we don't create another lockfile, since
	// we don't intend to read/write the target file itself.
	if strings.HasSuffix(path, ".lock") {
		return path
	}
	return path + lockPostfix
}

func getHardLinkCount(fi os.FileInfo) (uint64, bool) {
	// Although hardlinks on Windows are possible, Go does not currently expose the hardlinks associated to a file on windows
	return 0, false
}

// On Windows we can't unlink a file and then write to it, we have to overwrite it first.
// However, doing just that would cause problems - we have code that expects
// that if a file exists, then its contents must be well-formed.
// To remedy this, we rename the file before writing data to it.
func removeWithOverwrite(filePath string, fi os.FileInfo) error {
	renamedFilePath := filePath + ".tmp"

	err := os.Rename(filePath, renamedFilePath)
	if err != nil {
		// Attempt to delete the original file anyway.
		return trace.ConvertSystemError(os.Remove(filePath))
	}

	file, err := openOrRemoveOnFailure(renamedFilePath)
	if err != nil {
		return trace.Wrap(err)
	}
	defer file.Close()

	overwriteErr := overwriteFile(file, fi)
	removeErr := os.Remove(renamedFilePath)
	if overwriteErr != nil {
		return trace.Wrap(overwriteErr)
	}
	if removeErr != nil {
		return trace.ConvertSystemError(os.Remove(renamedFilePath))
	}
	return nil
}
