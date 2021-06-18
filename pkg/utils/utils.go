package utils

import (
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

// Generate a temp directory prepended with .sigstore
func StoreDir(timeStamp string) (string, error)  {
	storeDir := filepath.Join(".", ".sigstore", timeStamp)
	err := os.MkdirAll(storeDir, 0755)
	if err != nil {
		return "", err
	}
	return storeDir, nil
}

// Generate a temp directory prepended with .sigstore
//func TmpDir() (string, error)  {
//	dir, err := ioutil.TempDir("/tmp/", "")
//	if err != nil {
//		return "", err
//	}
//
//	err = os.Mkdir(dir + "/.sigstore", 0755)
//	if err != nil {
//		return "", err
//	}
//	return dir, nil
//}

// Download files from rawurls
// TODO: May want to replace this
func DownloadFile(file string, url string) error {
	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(file)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

// Opens a file for reading
func ReadFile(fileName string) ([]byte, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err = file.Close(); err != nil {
			panic(err)
		}
	}()
	b, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// Execute the targeted script to stdout|in|err
func ExecScript(scriptName string) (error) {
	err := os.Chmod(scriptName, 0700)
	if err != nil {
		return err
	}
	cmd := exec.Command("bash", "-c", scriptName)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return err
	}
	return nil
}