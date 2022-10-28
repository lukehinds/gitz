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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gabriel-vasile/mimetype"
	"github.com/google/go-github/v35/github"
	"github.com/lukehinds/gitz/pkg/githubapi"
	"github.com/lukehinds/gitz/pkg/utils"
	"github.com/sigstore/sigstore/pkg/generated/client/operations"
	"github.com/sigstore/sigstore/pkg/httpclients"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/tlog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

var (
	fulcioAddr string
	rekorAddr  string
	client     *github.Client
	ctx        = context.Background()
)

var supportedFileTypes = map[string]struct{}{
	"text/plain; charset=utf-8": {},
}

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a script using gitz",
	Long: `Sign a script using gitz and store within a GitHub repository.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		now := time.Now()
		timeStamp := strconv.FormatInt(now.UnixNano(), 10)

		shellScript := viper.GetString("script")
		payload, err := ioutil.ReadFile(shellScript)
		if err != nil {
			return err
		}

		// Lets check it is an actual script and someone is not
		// trying sign something non text/plain (e.g. should only be a script)
		mime, err := mimetype.DetectFile(shellScript)
		if err != nil {
			return err
		}
		if mime.String() != "text/plain; charset=utf-8" {
			return errors.New("unsupported mimetype")
		}

		//uncomment when we have all our sining files
		token := os.Getenv("GITHUB_AUTH_TOKEN")
		if token == "" {
			return errors.New("unauthorized: No token present")
		}

		// Retrieve idToken from oidc provider
		idToken, err := oauthflow.OIDConnect(
			viper.GetString("oidc-issuer"),
			viper.GetString("oidc-client-id"),
			viper.GetString("oidc-client-secret"),
			oauthflow.DefaultIDTokenGetter,
		)
		if err != nil {
			return err
		}
		fmt.Println("\nReceived OpenID Scope retrieved for account:", idToken.Subject)

		// Now OIDC has succeeded, build up the folder structure for saving signing materials
		storeDir, err := utils.StoreDir(timeStamp)

		signer, err := signature.NewDefaultECDSASignerVerifier()
		if err != nil {
			return err
		}

		pub, err := signer.PublicKey(ctx)
		if err != nil {
			return err
		}

		pubBytes, err := x509.MarshalPKIXPublicKey(pub)

		if err != nil {
			return err
		}

		proof, _, err := signer.Sign(ctx, []byte(idToken.Subject))
		if err != nil {
			return err
		}

		certResp, err := httpclients.GetCert(idToken, proof, pubBytes, viper.GetString("fulcio-server"))
		if err != nil {
			switch t := err.(type) {
			case *operations.SigningCertDefault:
				if t.Code() == http.StatusInternalServerError {
					return err
				}
			default:
				return err
			}
			os.Exit(1)
		}

		clientPEM, rootPEM := pem.Decode([]byte(certResp.Payload))

		certPEM := pem.EncodeToMemory(clientPEM)

		rootBlock, _ := pem.Decode([]byte(rootPEM))
		if rootBlock == nil {
			return err
		}

		certBlock, _ := pem.Decode([]byte(certPEM))
		if certBlock == nil {
			return err
		}

		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return err
		}

		fmt.Println("Received signing cerificate with serial number: ", cert.SerialNumber)

		signature, signedVal, err := signer.Sign(ctx, payload)
		if err != nil {
			panic(fmt.Sprintf("Error occurred while during artifact signing: %s", err))
		}

		fmt.Println("Sending entry to transparency log")
		tlogEntry, err := tlog.UploadToRekor(
			certPEM,
			signedVal,
			signature,
			viper.GetString("rekor-server"),
			payload,
		)
		if err != nil {
			return err
		}
		fmt.Println("Rekor entry successful. Index number: :", tlogEntry)

		// dump signature to file
		sigFile := fmt.Sprintf("%s/signature_%s.bin", storeDir, timeStamp)
		fulcioCert := fmt.Sprintf("%s/fulcio_cert_%s.pem", storeDir, timeStamp)

		err = ioutil.WriteFile(sigFile, signature, 0644)
		if err != nil {
			fmt.Println(err)
		}

		err = ioutil.WriteFile(fulcioCert, certPEM, 0644)
		if err != nil {
			fmt.Println(err)
		}

		// Setup GH token via oauth2
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)
		tc := oauth2.NewClient(ctx, ts)

		// Ontain instance of google/go-github client
		client := github.NewClient(tc)

		ref, err := githubapi.GetRef(ctx, client, viper.GetString("owner"), viper.GetString("repo"),
			timeStamp, viper.GetString("commit-branch"),
			viper.GetString("base-branch"))
		if err != nil {
			return errors.New(fmt.Sprintf("unable to get/create the commit reference: %s", err))
		}
		if ref == nil {
			return errors.New("no error where returned but the reference is nil")
		}

		filesForPR := fmt.Sprintf("%s,%s,%s", sigFile, fulcioCert, shellScript)
		tree, err := githubapi.GetTree(ctx, client, ref, filesForPR, viper.GetString("owner"),
			viper.GetString("repo"))
		if err != nil {
			return errors.New(fmt.Sprintf("unable to create the tree based on the provided files: %s\n", err))
		}

		if err := githubapi.PushCommit(ctx, client, ref, tree, viper.GetString("owner"),
			viper.GetString("repo"),
			viper.GetString("author-name"),
			viper.GetString("author-email"),
			viper.GetString("commit-message")); err != nil {
			return errors.New(fmt.Sprintf("unable to create the commit: %s\n", err))
		}

		if err := githubapi.CreatePR(ctx, client, viper.GetString("merge-branch-owner"),
			viper.GetString("merge-repo"),
			viper.GetString("owner"),
			viper.GetString("commit-branch"),
			viper.GetString("repo"),
			viper.GetString("pr-title"),
			viper.GetString("merge-branch"),
			viper.GetString("pr-text"),
		); err != nil {
			return errors.New(fmt.Sprintf("error while creating the pull request: %s", err))
		}

		return nil

	},
}

func init() {
	rootCmd.AddCommand(signCmd)
	signCmd.PersistentFlags().StringVar(&fulcioAddr, "fulcio-server", "https://fulcio.sigstore.dev", "address of sigstore PKI server")
	signCmd.PersistentFlags().StringVar(&rekorAddr, "rekor-server", "https://rekor.sigstore.dev", "address of rekor STL server")
	signCmd.PersistentFlags().String("oidc-issuer", "https://oauth2.sigstore.dev/auth", "OIDC provider to be used to issue ID token")
	signCmd.PersistentFlags().String("oidc-client-id", "sigstore", "client ID for application")
	signCmd.PersistentFlags().String("oidc-client-secret", "", "client secret for application")

	signCmd.PersistentFlags().String("author-email", "sign@sigstore.dev", "Used for the Author email")
	signCmd.PersistentFlags().String("author-name", "sigstore", "Used for the Author Name, default is \"sigstore\"")
	signCmd.PersistentFlags().String("base-branch", "main", "Name of branch to create the commit-branch from. (default \"main\")")
	signCmd.PersistentFlags().String("commit-branch", "", "Name of branch to create the commit in. If it does not already exists, it will be created using the base-branch parameter")
	signCmd.PersistentFlags().String("commit-message", "", "Content of the commit message.")
	signCmd.PersistentFlags().String("merge-branch", "main", "Name of branch to create the PR against (the one you want to merge your branch in via the PR). (default \"main\")")
	signCmd.PersistentFlags().String("merge-repo", "", "Name of repo to create the PR against. If not specified, the value of the --repo flag will be used.")
	signCmd.PersistentFlags().String("merge-repo-owner", "", "Name of the owner (user or org) of the repo to create the PR against. If not specified, the value of the --owner flag will be used.\"")
	signCmd.PersistentFlags().String("pr-text", "", "Text to put in the description of the pull request")
	signCmd.PersistentFlags().String("pr-title", "", " Title of the pull request. If not specified, no pull request will be created")
	signCmd.PersistentFlags().String("script", "", "Target script to sign")
	if err := viper.BindPFlags(signCmd.PersistentFlags()); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
