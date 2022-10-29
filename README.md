# `gitz`

### 🚨 `gitz` is not ready for serious use at this time 🚨

`gitz` is currently under heavy development, don't use it for anything important.

gitz is a tool to sign a thing (script, file, etc) with using sigstore keyless 
signing and then store the signature, sigstore certicate in a git repository.

It neatly maps the script, signature and public key using the commit sha.

gitz will also perform a verification of the signature and public key against
the commit sha when running the `install` command.

## Sign

Create a new github token and export it as an environment variable

```bash
export GITHUB_AUTH_TOKEN="your-token"
```

```bash
gitz sign --script path/to/script.sh --owner jdoe --repo myrepo --author-email jdoe@example.com --author-name jdoe --base-branch main --commit-branch pr-branch --commit-message "Pusshing new script" --pr-text "New script revision" --pr-title "New Script changes"
```

# Install

```bash
gitz sign --script path/to/script.sh --owner jdoe --repo myrepo script.sh
```
