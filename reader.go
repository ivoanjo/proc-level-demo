// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License (Version 2.0).
// This product includes software developed at Datadog (https://www.datadoghq.com/) Copyright 2025 Datadog, Inc.

// reader.go
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

const (
	// layoutMinorVersionLength defines the length of the layout minor version (uint16).
	layoutMinorVersionLength = 2
	// serviceNameMaxLength defines the maximum allowed length of service names.
	serviceNameMaxLength = 128
	// serviceEnvMaxLength defines the maximum allowed length of service environments.
	serviceEnvMaxLength = 128
	// runtimeIDLength defines the length of a UUID
	runtimeIDLength = 128
)

func nextString(rm remotememory.RemoteMemory, addr *libpf.Address, maxLen int) (string, error) {
	length := int(rm.Uint32(*addr))
	*addr += 4

	if length == 0 {
		return "", nil
	}

	if length > maxLen {
		return "", fmt.Errorf("APM string length %d exceeds maximum length of %d", length, maxLen)
	}

	raw := make([]byte, length)
	if _, err := rm.ReadAt(raw, int64(*addr)); err != nil {
		return "", errors.New("failed to read memory")
	}

	*addr += libpf.Address(length)
	return string(raw), nil
}

func getLayoutMinorVersion(rm remotememory.RemoteMemory, addr *libpf.Address) uint16 {
	layoutMinorVersion := rm.Uint16(*addr)
	*addr += layoutMinorVersionLength
	return layoutMinorVersion
}

func main() {
	// 1) Parse command‐line flags: we need the writer’s PID and (optionally) size.
	pidPtr := flag.Int("pid", 0, "PID of the writer process that created the [anon:process_level_storage] mapping")
	flag.Parse()

	if *pidPtr <= 0 {
		log.Fatalf("you must supply a positive -pid")
	}
	pid := *pidPtr

	// 2) Locate the start address of the anonymous mapping in /proc/<pid>/maps
	rm, readPtr, err := findAnonStart(pid)
	if err != nil {
		log.Fatalf("could not find mapping in /proc/%d/maps: %v", pid, err)
	}
	// The specification guarantees that the struct can only be extended by adding
	// new fields after the old ones.
	layoutMinorVersion := getLayoutMinorVersion(rm, &readPtr)

	serviceName, err := nextString(rm, &readPtr, serviceNameMaxLength)
	if err != nil {
		log.Fatalf("failed")
	}

	// Currently not used by us.
	serviceEnv, err := nextString(rm, &readPtr, serviceEnvMaxLength)
	if err != nil {
		log.Fatalf("failed")
	}

	var runtimeID string
	runtimeID, err = nextString(rm, &readPtr, runtimeIDLength)
	if err != nil {
		log.Fatalf("failed")
	}

	// 5) Print out what we recovered
	fmt.Println("---- Retrieved Shared Data ----")
	fmt.Printf("layoutMinorVersion = %d\n", layoutMinorVersion)
	fmt.Printf("serviceName        = %q\n", serviceName)
	fmt.Printf("serviceEnv         = %q\n", serviceEnv)
	fmt.Printf("runtimeID          = %q\n", runtimeID)

	fmt.Println()
}

func findAnonStart(pid int) (remotememory.RemoteMemory, libpf.Address, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return remotememory.RemoteMemory{}, libpf.Address(0), fmt.Errorf("open /proc/%d/maps: %w", pid, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := scanner.Text()
		// Typical line layout:
		//   00400000-0040c000 r-xp 00000000 08:02 131073      /usr/bin/cat
		//   7f8d3acd1000-7f8d3acd2000 rw-p 00000000 00:00 0
		parts := strings.Fields(line)
		if len(parts) != 5 { // unnammed anonymous mappings have no pathname
			continue
		}

		if parts[3] != "00:00" || parts[4] != "0" { // not associated with a file or device
			log.Printf("invalid inode: %s", parts[4])
			continue
		}

		if parts[1] != "rw-p" { // read, write, private (not executable)
			log.Printf("invalid permissions: %s", parts[1])
			continue
		}

		addrs := parts[0]
		bits := strings.SplitN(addrs, "-", 2)
		if len(bits) != 2 {
			return remotememory.RemoteMemory{}, libpf.Address(0), fmt.Errorf("unexpected address format %q", addrs)
		}
		startHex := bits[0]
		start, err := strconv.ParseUint(startHex, 16, 64)
		if err != nil {
			return remotememory.RemoteMemory{}, libpf.Address(0), fmt.Errorf("parse address %q: %w", startHex, err)
		}
		endHex := bits[1]
		end, err := strconv.ParseUint(endHex, 16, 64)
		if err != nil {
			return remotememory.RemoteMemory{}, libpf.Address(0), fmt.Errorf("parse address %q: %w", endHex, err)
		}
		size := end - start
		if size != 4096 {
			log.Printf("invalid size: %d", size)
			continue
		}
		startAddr := uintptr(start)
		log.Printf("Found mapping at address 0x%x (reading %d bytes)\n", startAddr, 8)

		rm := remotememory.NewProcessVirtualMemory(libpf.PID(pid))
		buf := make([]byte, 8)
		if rm.Read(libpf.Address(start), buf[:]) != nil {
			return remotememory.RemoteMemory{}, libpf.Address(0), fmt.Errorf("unable to read from mapping: %w", pid, err)
		}
		if string(buf) == "OTL-PROC" {
			readPtr := rm.Ptr(libpf.Address(startAddr + 8))
			if readPtr == 0 {
				log.Fatalf("failed to read agent process state pointer")
			}
			return rm, readPtr, nil
		}

	}
	if err := scanner.Err(); err != nil {
		return remotememory.RemoteMemory{}, libpf.Address(0), fmt.Errorf("scanning /proc/%d/maps: %w", pid, err)
	}
	return remotememory.RemoteMemory{}, libpf.Address(0), errors.New("mapping not found")
}
