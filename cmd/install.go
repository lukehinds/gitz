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
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/lukehinds/gitget/pkg/utils"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
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

		// lets see if we cannot use gh token and keep it for sign
		// TODO Remove this
		token := os.Getenv("GITHUB_AUTH_TOKEN")
		if token == "" {
			log.Fatal("unauthorized: No token present")
		}
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)
		tc := oauth2.NewClient(ctx, ts)

		// Ontain instance of google/go-github client
		ghClient := github.NewClient(tc)
		//ctx := context.Background()
		//ghClient := github.NewClient(nil)
		// TODO remove this

		getFiles, _ := pterm.DefaultSpinner.Start("Retrieving signed materials and target script for tag: ", tag)

		// Get the latest release tag
		getLatestRelease, getLatestReleaseResp, err := ghClient.Repositories.GetLatestRelease(ctx, owner, repo)
		if err != nil {
			fmt.Errorf("Repositories.GetLatestRelease returned error: %v\n%v", err, getLatestReleaseResp.Body)
		}

		switch getLatestReleaseResp.StatusCode{
		case 403:
			//fmt.Println(err)
			getFiles.Fail("GitHub rate limit active ", getLatestReleaseResp.Rate)
		}

		// Get the sha for the latest release commit
		release, resp, err := ghClient.Repositories.GetReleaseByTag(ctx, owner, repo, *getLatestRelease.TagName)
		if err != nil {
			fmt.Errorf("Repositories.GetReleaseByTag returned error: %v\n%v", err, resp.Body)
		}

		// get the commit that was used as a tag against the release, this then allows us to iterate
		// over the files in the release / commit
		commits, getCommitresp, err := ghClient.Repositories.GetCommit(ctx, owner, repo, *release.TargetCommitish)
		if err != nil {
			getFiles.Fail(err)
			//fmt.Println(err)
		}
		if getCommitresp.StatusCode != 200 {
			getFiles.Fail("Network connection failed with http code: ", resp.StatusCode)
			//fmt.Println(err)
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
				certName = "/tmp/" + filepath.Base(*changeCommits.Filename)
			case ".bin":
				sigName = "/tmp/" + filepath.Base(*changeCommits.Filename)
			case ".sh":
				scriptName = "/tmp/" + filepath.Base(*changeCommits.Filename)
				scriptPrettyName = *changeCommits.Filename
			}
			err := utils.DownloadFile("/tmp/" + filepath.Base(*changeCommits.Filename), *changeCommits.RawURL)
			if err != nil {
				getFiles.Fail(err)
				//fmt.Println(err)
			}
		}

		getFiles.Success()

		// Verify the signature
		verifySigning, _ := pterm.DefaultSpinner.Start("Performing signing verification  of " + scriptPrettyName)

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
			log.Fatalf("failed to read sig from %s: %s", "signature.bin", err)
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
		// TODO: clean up by removing all files in temp directory
	},
}

func init() {
	rootCmd.AddCommand(installCmd)
	installCmd.PersistentFlags().String("tag", "latest", "The release tag (version)")
}
