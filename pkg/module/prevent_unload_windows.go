// pkcs11mod
// Copyright (C) 2022  Namecoin Developers
//
// pkcs11mod is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// pkcs11mod is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with pkcs11mod; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
//
// Portions Copyright (C) 2021 Andreas @ryrun (MIT license)

package module

import (
	"log"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"time"
	"unsafe"
)

// This hack prevents a segfault if the application tries to unload pkcs11mod.
// We use the syscall package because importing the higher-level goxsys/windows
// package causes Mozilla Electrolysis (E10S) sandbox process to crash.
// See the following references:
// https://github.com/golang/go/issues/11100#issuecomment-489066651
// https://github.com/golang/go/issues/11100#issuecomment-932638093
// https://blogs.msmvps.com/vandooren/2006/10/09/preventing-a-dll-from-being-unloaded-by-the-app-that-uses-it/
// https://stackoverflow.com/a/14436845
// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexa?redirectedfrom=MSDN#parameters
// https://github.com/pipelined/vst2/blob/bc659a1443b585c376cc25a6d13614488c9fa4ee/plugin_export_windows.go#L11-L34
func preventUnload() {
	// Copied nearly verbatim from https://github.com/pipelined/vst2
	const (
		GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS = 4
		GET_MODULE_HANDLE_EX_FLAG_PIN          = 1
	)
	var (
		kernel32, _          = syscall.LoadLibrary("kernel32.dll")
		getModuleHandleEx, _ = syscall.GetProcAddress(kernel32, "GetModuleHandleExW")
		handle               uintptr
	)
	defer func(handle syscall.Handle) {
		err := syscall.FreeLibrary(handle)
		if err != nil {
			log.Printf("pkcs11mod: Can't unload kernel32 lib: %s", err)
			return
		}
	}(kernel32)
	if _, _, callErr := syscall.SyscallN(uintptr(getModuleHandleEx), 3, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN, reflect.ValueOf(preventUnload).Pointer(), uintptr(unsafe.Pointer(&handle))); callErr != 0 {
		log.Printf("pkcs11mod: Can't pin module: %d", callErr)
		return
	}
}

// This hack prevents a hang if the application tries to wait for all
// background threads to finish before exiting the process.  Affected
// applications include Unity and NSS certutil.
// See the following references:
// https://github.com/golang/go/issues/11100#issuecomment-389539527
// https://github.com/golang/go/issues/11100#issuecomment-487840893
func exitSoon() {
	exePath, err := os.Executable()
	if err != nil {
		log.Printf("pkcs11mod: Error detecting executable name: %s", err)
		return
	}

	exe := filepath.Base(exePath)

	shouldForceExitSoon := false

	switch exe {
	case "certutil.exe":
		shouldForceExitSoon = true
	default:
		log.Printf("pkcs11mod: Unknown exe name '%s'.  This is probably fine, but if you see this application hang on exit immediately after this message was logged, consider reporting a bug to pkcs11mod; provide the exe name from this log message.\n", exe)
	}

	if shouldForceExitSoon {
		go func() {
			time.Sleep(5 * time.Second)
			os.Exit(0)
		}()
	}
}
