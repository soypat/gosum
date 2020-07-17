/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

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
package cmd

import (
	"crypto"
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/spf13/cobra"
	_ "golang.org/x/crypto/blake2b"
	_ "golang.org/x/crypto/blake2s"
	_ "golang.org/x/crypto/md4"
	_ "golang.org/x/crypto/ripemd160"
	_ "golang.org/x/crypto/sha3"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

var alg crypto.Hash
var algorithmFlag string
var recursiveFlag bool
var baseFlag int

const (
	defaultAlgorithm = crypto.SHA256
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "gosum",
	Short: "Calculate hash sums using various algorithms",
	Long: `Call gosum indicating algorithm desired.
passing "*" as argument processes all files in current directory.

Available algorithms. quoted literal is expected flag value
	"md4":         crypto.MD4,
	"md5":         crypto.MD5,
	"sha1":        crypto.SHA1,
	"sha256":      crypto.SHA256,
	"sha2":        crypto.SHA256,
	"sha384":      crypto.SHA384,
	"sha512":      crypto.SHA256,
	"sha3-256":    crypto.SHA3_256,
	"sha3-384":    crypto.SHA3_384,
	"sha3-512":    crypto.SHA3_512,
	"sha512-224":  crypto.SHA512_224,
	"sha512-256":  crypto.SHA512_256,
	"blake2s-256": crypto.BLAKE2s_256,
	"blake2b-256": crypto.BLAKE2b_256,
	"blake2b-384": crypto.BLAKE2b_384,
	"blake2b-512": crypto.BLAKE2b_512,
	"ripemd160":   crypto.RIPEMD160,

	example:
		gosum -a sha1 file1.txt file2.txt ...
		gosum -a sha3-256 "*"
		gosum -r -a md4 "*"

It is recommended to use quote literals when passing entire directories
`,

	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("not enough arguments")
		}
		var present bool
		alg, present = algorithms[algorithmFlag]
		if !present {
			return fmt.Errorf("algorithm %s not found", algorithmFlag)
		}
		if baseFlag != 16 && baseFlag != 64 && baseFlag != 32  {
			return fmt.Errorf("unknown base %d. See help", baseFlag)
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		if err := runner(args); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

func runner(args []string) error {
	var filenames []string
	if args[0] == "*" {
		var itemsFound []os.FileInfo
		var err error
		if recursiveFlag {
			err = filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
				if !info.IsDir() {
					filenames = append(filenames, filepath.Join(path))
				}
				return nil
			})
		} else {
			itemsFound, err = ioutil.ReadDir(".")
			for _, f := range itemsFound {
				if !f.IsDir() {
					filenames = append(filenames, f.Name())
				}
			}
		}
		if err != nil {
			return err
		}
	} else {
		for _, fname := range args {
			f, err := os.Stat(fname)
			if err != nil {
				return err
			}
			if f.IsDir() {
				continue
			}
			filenames = append(filenames, fname)
		}
	}
	if len(filenames) == 0 {
		return fmt.Errorf("no files found")
	}

	// finish prechecks
	var hashes, names []string
	for _, fname := range filenames {
		f, err := os.Open(fname)
		if err != nil {
			return err
		}
		defer f.Close()
		h := alg.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		if baseFlag == 16 {
			hashes = append(hashes, hex.EncodeToString(h.Sum(nil)))
		} else if baseFlag == 64 {
			hashes = append(hashes, base64Encode(h.Sum(nil)))
		} else if baseFlag == 32 {
			hashes = append(hashes, base32Encode(h.Sum(nil)))
		}

		names = append(names, f.Name())
	}
	fmt.Printf("%s job:\n", algorithmFlag)
	for i := range hashes {
		fmt.Printf("%s\t%s\n", hashes[i], names[i])
	}
	return nil
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var algorithms = map[string]crypto.Hash{
	"md4":         crypto.MD4,
	"md5":         crypto.MD5,
	"sha1":        crypto.SHA1,
	"sha256":      crypto.SHA256,
	"sha2":        crypto.SHA256,
	"sha384":      crypto.SHA384,
	"sha512":      crypto.SHA256,
	"sha3-256":    crypto.SHA3_256,
	"sha3-384":    crypto.SHA3_384,
	"sha3-512":    crypto.SHA3_512,
	"sha512-224":  crypto.SHA512_224,
	"sha512-256":  crypto.SHA512_256,
	"blake2s-256": crypto.BLAKE2s_256,
	"blake2b-256": crypto.BLAKE2b_256,
	"blake2b-384": crypto.BLAKE2b_384,
	"blake2b-512": crypto.BLAKE2b_512,
	"ripemd160":   crypto.RIPEMD160,
}

func init() {
	rootCmd.Flags().StringVarP(&algorithmFlag, "algorithm", "a", "sha256", "Algorithm used to compute hash. call help for all available")
	rootCmd.Flags().BoolVarP(&recursiveFlag, "recursive", "r", false, "Recursive search in subdirectories. Needs \"*\" as argument")
	rootCmd.Flags().IntVarP(&baseFlag, "base", "b",16,"Base of hash output. 16, 32 or 64 available")
}

func base64Encode(input []byte) (string) {
	eb := make([]byte, base64.StdEncoding.EncodedLen(len(input)))
	base64.StdEncoding.Encode(eb, input)
	return string(eb)
}

func base32Encode(input []byte) (string) {
	eb := make([]byte, base32.StdEncoding.EncodedLen(len(input)))
	base32.StdEncoding.Encode(eb, input)
	return string(eb)
}