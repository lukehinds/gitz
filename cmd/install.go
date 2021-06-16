//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/lukehinds/sget/pkg/utils"
	"github.com/spf13/viper"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"

	"github.com/google/go-github/v35/github"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

// ecdsaSig is a datatype for a ECDSA Signature
type ecdsaSig struct {
	R *big.Int
	S *big.Int
}

// installCmd represents the install command
var installCmd = &cobra.Command{
	Use:   "install",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		tag := viper.GetString("tag")
		owner := viper.GetString("owner")
		repo := viper.GetString("repo")
		pterm.Info.Println("Running sigstore's safeget crypto downloader")
		tmpDir, err := utils.TmpDir()
		if err != nil {
			log.Fatal(err)
		}
		// lets see if we cannot use gh token and keep it for sign
		ctx := context.Background()
		ghClient := github.NewClient(nil)

		getFiles, _ := pterm.DefaultSpinner.Start("Retrieving signed materials and target script for tag: ", tag)

		// Get the latest release tag
		getLatestRelease, getLatestReleaseResp, err := ghClient.Repositories.GetLatestRelease(ctx, owner, repo)
		if err != nil {
			fmt.Errorf("Repositories.GetLatestRelease returned error: %v\n%v", err, getLatestReleaseResp.Body)
		}

		// Get the sha for the latest release commit
		release, resp, err := ghClient.Repositories.GetReleaseByTag(ctx, owner, repo, *getLatestRelease.TagName)
		if err != nil {
			fmt.Errorf("Repositories.GetReleaseByTag returned error: %v\n%v", err, resp.Body)
		}

		// get the commit that was used as a tag against the release, this then allows us to iterate
		// over the files in the release / commit
		commits, resp, err := ghClient.Repositories.GetCommit(ctx, owner, repo, *release.TargetCommitish)
		if err != nil {
			getFiles.Fail(err)
		}
		if resp.StatusCode != 200 {
			getFiles.Fail("Network connection failed with http code: ", resp.StatusCode)
		}

		// Gather files we need for verification
		var scriptName string
		var scriptPrettyName string
		var certName string
		var sigName string

		for _, changeCommits := range commits.Files {
			// we need these for being able to access them later
			switch filepath.Ext(*changeCommits.Filename) {
			case ".pem":
				certName = filepath.Base(tmpDir + "/" + *changeCommits.Filename)
			case ".sig":
				sigName = filepath.Base(tmpDir + "/" + *changeCommits.Filename)
			case ".sh":
				scriptName = filepath.Base(tmpDir + "/" + *changeCommits.Filename)
				scriptPrettyName = *changeCommits.Filename
			}
			err := utils.DownloadFile(tmpDir + "/" + filepath.Base(*changeCommits.Filename), *changeCommits.RawURL)
			if err != nil {
				getFiles.Fail(err)
			}
		}

		getFiles.Success()

		// Verify the signature
		verifySigning, _ := pterm.DefaultSpinner.Start("Performing signing verification  of " + scriptPrettyName)
		pterm.Info.Println("found a sigstore signed identity trust root from: lhinds@redhat.com")
		certFile, err := utils.ReadFile(certName)
		if err != nil {
			log.Fatal("certfile read error: ", err)
		}

		// Extract the public key from the signing cert as we need this to verify
		block, _ := pem.Decode(certFile)
		var cert* x509.Certificate
		cert, _ = x509.ParseCertificate(block.Bytes)
		ecdsaPublicKey := cert.PublicKey.(*ecdsa.PublicKey)

		// Generate the sha256hash of the artifact
		hash := sha256.New()
		in, err := os.Open(scriptName)
		if err != nil {
			log.Fatal(err)
		}
		defer in.Close()
		io.Copy(hash, in)

		// Read in the signature file
		raw, err := ioutil.ReadFile(sigName)
		if err != nil {
			log.Fatalf("failed to read sig from %s: %s", "signature.sig", err)
		}

		// Marshall out the signature file to asn1
		sig := &ecdsaSig{}
		_, err = asn1.Unmarshal(raw, sig)
		if err != nil {
			log.Fatalf("invalid signature data")
		}

		if sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
			log.Fatalf("signature contained zero or negative values")
		}

		// Verify the actual signature signing, if verify fails exit with a failure code
		if !ecdsa.Verify(ecdsaPublicKey, hash.Sum(nil), sig.R, sig.S) {
			verifySigning.Fail()
			os.Exit(1)
		} else {
			verifySigning.Success()
		}

		pterm.Info.Println("safeget will now handover to script execution of: " + scriptPrettyName)

		// Execute the script in question
		err = utils.ExecScript(scriptName)
		if err != nil {
			log.Fatal(err)
		}

		// clean up by removing all files in temp directory
		os.RemoveAll(tmpDir)
	},
}

func init() {
	rootCmd.AddCommand(installCmd)
	installCmd.PersistentFlags().String("tag", "latest", "The release tag (version)")
}
