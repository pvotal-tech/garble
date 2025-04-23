// Copyright (c) 2025, PVotal Inc.
// See LICENSE for licensing information.

package sourceSeed

import (
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/text/unicode/norm"
	"lukechampine.com/blake3"
)

var DIRS_TO_HASH = []string{"internal"}
var FILES_TO_HASH = []string{"go.mod", "go.sum"}

const SEED_SIZE = 32

// Writer that strip some characters and pipe into a Unicode normalizer
type CustomCanonicalWriter struct {
	writer io.Writer
}

// Generate a seed from the source code itself
// The hash uses Blake3
// The files are canonicalized using the unicode norm package and stripping all forms of whitespace
// A 0xFF byte is added to the hash before each file and the lowercased relative path
// The standalone files are hashed, then the directories are hashed
//
// When hashing a directory, only the .go files are hashed, and those starting with gen_ are excluded
func GetSourceSeed(baseDir string, additionnalFiles []string) ([]byte, error) {
	// Hash all the source files
	hasher := blake3.New(SEED_SIZE, nil)

	{
		// Pipe the file content to the writer
		normalizedWriter := norm.NFKC.Writer(hasher)
		defer normalizedWriter.Close()
		canonicalWriter := newCanonicalWriter(normalizedWriter)

		filesToHash := FILES_TO_HASH
		dirsToHash := DIRS_TO_HASH

		// Hash the additionnal files passed in the CLI
		for _, path := range additionnalFiles {
			statInfo, err := os.Stat(baseDir + "/" + path)

			if err != nil {
				log.Printf("[WARN] error computing seed reading path %s, ignoring: %s", path, err)
				continue
			}

			if statInfo.IsDir() {
				dirsToHash = append(dirsToHash, path)
			} else if statInfo.Mode().IsRegular() {
				filesToHash = append(filesToHash, path)
			}
		}

		// Hash the standalone files
		for _, path := range filesToHash {
			err := addFileToWriter(baseDir, path, canonicalWriter, hasher)

			if err != nil {
				return nil, err
			}
		}

		// Hash the dirs
		for _, dir := range dirsToHash {
			err := addDirToWriter(baseDir, dir, canonicalWriter, hasher)

			if err != nil {
				return nil, err
			}
		}
	}

	// Run a KDF on the hash using a context string
	seed := make([]byte, SEED_SIZE)
	hasher.Sum(seed[:0])
	blake3.DeriveKey(seed, "[garble-pvotal] v1 obfuscation", seed)

	return seed, nil
}

func newCanonicalWriter(writer io.Writer) CustomCanonicalWriter {
	return CustomCanonicalWriter{
		writer,
	}
}

func (w CustomCanonicalWriter) Write(input []byte) (n int, err error) {
	buf := make([]byte, len(input))

	i := 0
	for _, b := range input {
		// Stripped characters:
		//  0x20: Space
		//	0x09: Tab
		//	0x0d: CR
		//	0x0b: LF
		if b != 0x20 && b != 0x09 && b != 0x0d && b != 0x0a {
			buf[i] = b
			i++
		}
	}

	_, err = w.writer.Write(buf[:i])

	if err != nil {
		return len(input), err
	}

	return len(input), nil
}

func addFileToWriter(baseDir string, path string, writer io.Writer, hasher *blake3.Hasher) error {
	// Write a delimiter to domain separate the files.
	// 0xF8-0xFF are never used in unicode, so we use it
	// Writes it directly into the hasher so it doesn't get stripped
	hasher.Write([]byte{0xFE})

	cleanedPath := filepath.Clean(path)

	// Lowercase path
	writer.Write([]byte(strings.ToLower(cleanedPath)))

	hasher.Write([]byte{0xFF})

	file, err := os.Open(baseDir + "/" + cleanedPath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteTo(writer)

	return err
}

func addDirToWriter(baseDir string, path string, writer io.Writer, hasher *blake3.Hasher) error {
	// NOTE: We need to make sure the path are canonicalized and always in the same order.
	// The docs of WalkDir mentions the order is deterministic
	err := filepath.WalkDir(baseDir+"/"+path, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		relativePath := strings.TrimPrefix(path, baseDir+"/")

		// We only want to hash the go files that are not generated
		if strings.HasSuffix(path, ".go") && !strings.Contains(path, "gen_") {
			err = addFileToWriter(baseDir, relativePath, writer, hasher)

			if err != nil {
				return err
			}
		}

		return nil
	})

	return err
}
