package githubapi

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/go-github/v35/github"
	"io/ioutil"
	"strings"
	"time"
)

// GetRef returns the commit branch reference object if it exists or creates it
// from the base branch before returning it.
func GetRef(ctx context.Context, client *github.Client, sourceOwner string, sourceRepo string, timeStamp string, commitBranch string, baseBranch string) (ref *github.Reference, err error) {
	if ref, _, err = client.Git.GetRef(ctx, sourceOwner, sourceRepo, "refs/heads/"+commitBranch); err == nil {
		return ref, nil
	}

	if commitBranch == baseBranch {
		return nil, errors.New("The commit branch does not exist but `-base-branch` is the same as `-commit-branch`")
	}

	if baseBranch == "" {
		return nil, errors.New("The `-base-branch` should not be set to an empty string when the branch specified by `-commit-branch` does not exists")
	}

	var baseRef *github.Reference
	if baseRef, _, err = client.Git.GetRef(ctx, sourceOwner, sourceRepo, "refs/heads/"+baseBranch); err != nil {
		return nil, err
	}
	newRef := &github.Reference{Ref: github.String("refs/heads/" + commitBranch), Object: &github.GitObject{SHA: baseRef.Object.SHA}}
	ref, _, err = client.Git.CreateRef(ctx, sourceOwner, sourceRepo, newRef)
	return ref, err
}

// GetTree generates the tree to commit based on the given files and the commit
// of the ref you got in getRef.
func GetTree(ctx context.Context, client *github.Client, ref *github.Reference, sourceFiles string, sourceOwner string,
	sourceRepo string) (tree *github.Tree, err error) {
	// Create a tree with what to commit.
	entries := []*github.TreeEntry{}

	// Load each file into the tree.
	for _, fileArg := range strings.Split(sourceFiles, ",") {
		file, content, err := getFileContent(fileArg)

		if err != nil {
			return nil, err
		}
		entries = append(entries, &github.TreeEntry{Path: github.String(file), Type: github.String("blob"), Content: github.String(string(content)), Mode: github.String("100644")})
	}

	tree, _, err = client.Git.CreateTree(ctx, sourceOwner, sourceRepo, *ref.Object.SHA, entries)
	return tree, err
}

// getFileContent loads the local content of a file and return the target name
// of the file in the target repository and its contents.
func getFileContent(fileArg string) (targetName string, b []byte, err error) {
	var localFile string
	files := strings.Split(fileArg, ":")
	switch {
	case len(files) < 1:
		return "", nil, errors.New("empty `-files` parameter")
	case len(files) == 1:
		localFile = files[0]
		targetName = files[0]
	default:
		localFile = files[0]
		targetName = files[1]
	}

	b, err = ioutil.ReadFile(localFile)
	return targetName, b, err
}

// pushCommit creates the commit in the given reference using the given tree.
func PushCommit(ctx context.Context, client *github.Client, ref *github.Reference, tree *github.Tree,
	sourceOwner string, sourceRepo string, authorName string, authorEmail string, commitMessage string) (err error) {
	// Get the parent commit to attach the commit to.
	parent, _, err := client.Repositories.GetCommit(ctx, sourceOwner, sourceRepo, *ref.Object.SHA)
	if err != nil {
		return err
	}
	// This is not always populated, but is needed.
	parent.Commit.SHA = parent.SHA

	// Create the commit using the tree.
	date := time.Now()
	author := &github.CommitAuthor{Date: &date, Name: &authorName, Email: &authorEmail}
	commit := &github.Commit{Author: author, Message: &commitMessage, Tree: tree, Parents: []*github.Commit{parent.Commit}}
	newCommit, _, err := client.Git.CreateCommit(ctx, sourceOwner, sourceRepo, commit)
	if err != nil {
		return err
	}

	// Attach the commit to the master branch.
	ref.Object.SHA = newCommit.SHA
	_, _, err = client.Git.UpdateRef(ctx, sourceOwner, sourceRepo, ref, false)
	return err
}

// createPR creates a pull request. Based on: https://godoc.org/github.com/google/go-github/github#example-PullRequestsService-Create
func CreatePR(ctx context.Context, client *github.Client, prRepoOwner string, prRepo string, sourceOwner string,
	commitBranch string, sourceRepo string, prSubject string, prBranch string, prDescription string) (err error) {

	if prSubject == "" {
		return errors.New("missing `-pr-title` flag; skipping PR creation")
	}

	if prRepoOwner != "" && prRepoOwner != sourceOwner {
		commitBranch = fmt.Sprintf("%s:%s", sourceOwner, commitBranch)
	} else {
		prRepoOwner = sourceOwner
	}

	if prRepo == "" {
		prRepo = sourceRepo
	}
	newPR := &github.NewPullRequest{
		Title:               &prSubject,
		Head:                &commitBranch,
		Base:                &prBranch,
		Body:                &prDescription,
		MaintainerCanModify: github.Bool(true),
	}

	pr, _, err := client.PullRequests.Create(ctx, prRepoOwner, prRepo, newPR)
	if err != nil {
		return err
	}

	fmt.Printf("PR created: %s\n", pr.GetHTMLURL())
	return nil
}