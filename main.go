package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

const (
	caseInsensitiveEnv = runtime.GOOS == "windows"
	// unpackedOkay is a sentinel zero-byte file to indicate that the Go
	// version was downloaded and unpacked successfully.
	unpackedOkay = ".unpacked-success"
)

func init() {
	http.DefaultTransport = &userAgentTransport{http.DefaultTransport}
}

func main() {
	flag.Parse()

	switch flag.Arg(0) {
	// Searches the google archive index for install-able Go versions
	case "search":
		versions, err := search(flag.Arg(1))
		if err != nil {
			log.Fatalln(err)
		}
		for _, version := range versions {
			fmt.Println(version)
		}
	// Lists installed Go versions. Any version installed by `go get golang.org/dl/VERSION` will also show up here.
	case "installed":
		versions, err := installed(flag.Arg(1))
		if err != nil {
			log.Fatalln(err)
		}
		for _, version := range versions {
			fmt.Println(version)
		}
	case "install":
		if err := install(flag.Arg(1)); err != nil {
			log.Fatalln(err)
		}
	case "use":
		log.Fatalln("TODO")
	default:
		log.Fatalln("invalid command:", flag.Arg(0))
	}
}

func search(pattern string) ([]string, error) {
	index, err := dlIndex()
	if err != nil {
		return nil, err
	}

	if pattern == "" {
		pattern = "*"
	}

	var versions []string

	for _, src := range index {
		splitSlash := strings.Split(src, "/")
		lastPath := splitSlash[len(splitSlash)-1]
		goVersion := strings.TrimSuffix(lastPath, archiveSuffix())
		matched, err := filepath.Match(pattern, goVersion)
		if err != nil {
			log.Fatalln(err)
		}
		if matched {
			versions = append(versions, goVersion)
		}
	}

	return versions, nil
}

func installed(pattern string) ([]string, error) {
	if pattern == "" {
		pattern = "*"
	}
	root, err := installRoot()
	if err != nil {
		log.Fatalln(err)
	}
	matches, err := filepath.Glob(filepath.Join(root, pattern))
	if err != nil {
		log.Fatalln(err)
	}

	var versions []string

	for _, match := range matches {
		versions = append(versions, filepath.Base(match))
	}

	return versions, nil
}

func install(version string) error {
	installParent, err := installRoot()
	if err != nil {
		return err
	}
	targetDir := filepath.Join(installParent, version)
	if _, err := os.Stat(filepath.Join(targetDir, unpackedOkay)); err == nil {
		log.Printf("%s: already downloaded in %v", version, targetDir)
		return nil
	}
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return err
	}
	goURL := "https://storage.googleapis.com/golang/" + version + archiveSuffix()
	res, err := http.Get(goURL)
	if err != nil {
		return err
	}
	if res.StatusCode == http.StatusNotFound {
		return fmt.Errorf("no binary release of %v for %v/%v at %v", version, runtime.GOOS, runtime.GOARCH, goURL)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %v checking size of %v", http.StatusText(res.StatusCode), goURL)
	}
	base := path.Base(goURL)
	archiveFile := filepath.Join(targetDir, base)
	if fi, err := os.Stat(archiveFile); err != nil || fi.Size() != res.ContentLength {
		if err != nil && !os.IsNotExist(err) {
			// Something weird. Don't try to download.
			return err
		}
		if err := copyFromURL(archiveFile, goURL); err != nil {
			return fmt.Errorf("error downloading %v: %v", goURL, err)
		}
		fi, err = os.Stat(archiveFile)
		if err != nil {
			return err
		}
		if fi.Size() != res.ContentLength {
			return fmt.Errorf("downloaded file %s size %v doesn't match server size %v", archiveFile, fi.Size(), res.ContentLength)
		}
	}

	// Go versions prior to 1.5.4 do not have a sha256 url.
	if compareSemVer(version, "go1.5.4") > -1 {
		wantSHA, err := slurpURLToString(goURL + ".sha256")
		if err != nil {
			return err
		}
		if err := verifySHA256(archiveFile, strings.TrimSpace(wantSHA)); err != nil {
			return fmt.Errorf("error verifying SHA256 of %v: %v", archiveFile, err)
		}
	}

	log.Printf("Unpacking %v ...", archiveFile)
	if err := unpackArchive(targetDir, archiveFile); err != nil {
		return fmt.Errorf("extracting archive %v: %v", archiveFile, err)
	}
	if err := ioutil.WriteFile(filepath.Join(targetDir, unpackedOkay), nil, 0644); err != nil {
		return err
	}
	log.Printf("Success. You may now run '%v'", version)
	return nil
}

func dlIndex() ([]string, error) {
	res, err := http.Get("https://storage.googleapis.com/go-builder-data/dl-index.txt")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var index []string
	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		src := scanner.Text()
		if strings.HasSuffix(src, archiveSuffix()) {
			index = append(index, src)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return index, nil
}

// The Go downloader binaries use this header, so let's mimick that.
// Ref: https://go.googlesource.com/dl/+/refs/heads/master/internal/version/version.go#458
func setUserAgent(h http.Header) {
	version := runtime.Version()
	if strings.Contains(version, "devel") {
		// Strip the SHA hash and date. We don't want spaces or other tokens (see RFC2616 14.43)
		version = "devel"
	}
	h.Set("User-Agent", "golang-x-build-version/"+version)
}

func archiveSuffix() string {
	goos := runtime.GOOS
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	arch := runtime.GOARCH
	if goos == "linux" && runtime.GOARCH == "arm" {
		arch = "armv6l"
	}
	return "." + goos + "-" + arch + ext
}

func goBinExe() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

func installRoot() (string, error) {
	home, err := homeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %v", err)
	}
	return filepath.Join(home, "sdk"), nil
}

func goRoot(version string) (string, error) {
	sdk, err := installRoot()
	if err != nil {
		return "", fmt.Errorf("failed to get sdk directory: %v", err)
	}
	return filepath.Join(sdk, version), nil
}

func homeDir() (string, error) {
	switch runtime.GOOS {
	case "plan9":
		return "", fmt.Errorf("%q not yet supported", runtime.GOOS)
	case "windows":
		if dir := os.Getenv("USERPROFILE"); dir != "" {
			return dir, nil
		}
		return "", errors.New("can't find user home directory; %USERPROFILE% is empty")
	default:
		if dir := os.Getenv("HOME"); dir != "" {
			return dir, nil
		}
		if u, err := user.Current(); err == nil && u.HomeDir != "" {
			return u.HomeDir, nil
		}
		return "", errors.New("can't find user home directory; $HOME is empty")
	}
}

func compareSemVer(v, w string) int {
	v = strings.Replace(v, "go", "v", 1)
	w = strings.Replace(w, "go", "v", 1)
	return semver.Compare(v, w)
}

// copyFromURL downloads srcURL to dstFile.
func copyFromURL(dstFile, srcURL string) (err error) {
	f, err := os.Create(dstFile)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(dstFile)
		}
	}()
	c := &http.Client{
		Transport: &userAgentTransport{&http.Transport{
			// It's already compressed. Prefer accurate ContentLength.
			// (Not that GCS would try to compress it, though)
			DisableCompression: true,
			DisableKeepAlives:  true,
			Proxy:              http.ProxyFromEnvironment,
		}},
	}
	res, err := c.Get(srcURL)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return errors.New(res.Status)
	}
	pw := &progressWriter{w: f, total: res.ContentLength}
	n, err := io.Copy(pw, res.Body)
	if err != nil {
		return err
	}
	if res.ContentLength != -1 && res.ContentLength != n {
		return fmt.Errorf("copied %v bytes; expected %v", n, res.ContentLength)
	}
	pw.update() // 100%
	return f.Close()
}

type progressWriter struct {
	w     io.Writer
	n     int64
	total int64
	last  time.Time
}

func (p *progressWriter) update() {
	end := " ..."
	if p.n == p.total {
		end = ""
	}
	fmt.Fprintf(os.Stderr, "Downloaded %5.1f%% (%*d / %d bytes)%s\n",
		(100.0*float64(p.n))/float64(p.total),
		ndigits(p.total), p.n, p.total, end)
}
func ndigits(i int64) int {
	var n int
	for ; i != 0; i /= 10 {
		n++
	}
	return n
}
func (p *progressWriter) Write(buf []byte) (n int, err error) {
	n, err = p.w.Write(buf)
	p.n += int64(n)
	if now := time.Now(); now.Unix() != p.last.Unix() {
		p.update()
		p.last = now
	}
	return
}

// slurpURLToString downloads the given URL and returns it as a string.
func slurpURLToString(url_ string) (string, error) {
	res, err := http.Get(url_)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %v", url_, res.Status)
	}
	slurp, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("reading %s: %v", url_, err)
	}
	return string(slurp), nil
}

// unpackArchive unpacks the provided archive zip or tar.gz file to targetDir,
// removing the "go/" prefix from file entries.
func unpackArchive(targetDir, archiveFile string) error {
	switch {
	case strings.HasSuffix(archiveFile, ".zip"):
		return unpackZip(targetDir, archiveFile)
	case strings.HasSuffix(archiveFile, ".tar.gz"):
		return unpackTarGz(targetDir, archiveFile)
	default:
		return errors.New("unsupported archive file")
	}
}

// unpackTarGz is the tar.gz implementation of unpackArchive.
func unpackTarGz(targetDir, archiveFile string) error {
	r, err := os.Open(archiveFile)
	if err != nil {
		return err
	}
	defer r.Close()
	madeDir := map[string]bool{}
	zr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	tr := tar.NewReader(zr)
	for {
		f, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if !validRelPath(f.Name) {
			return fmt.Errorf("tar file contained invalid name %q", f.Name)
		}
		rel := filepath.FromSlash(strings.TrimPrefix(f.Name, "go/"))
		abs := filepath.Join(targetDir, rel)
		fi := f.FileInfo()
		mode := fi.Mode()
		switch {
		case mode.IsRegular():
			// Make the directory. This is redundant because it should
			// already be made by a directory entry in the tar
			// beforehand. Thus, don't check for errors; the next
			// write will fail with the same error.
			dir := filepath.Dir(abs)
			if !madeDir[dir] {
				if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
					return err
				}
				madeDir[dir] = true
			}
			wf, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode.Perm())
			if err != nil {
				return err
			}
			n, err := io.Copy(wf, tr)
			if closeErr := wf.Close(); closeErr != nil && err == nil {
				err = closeErr
			}
			if err != nil {
				return fmt.Errorf("error writing to %s: %v", abs, err)
			}
			if n != f.Size {
				return fmt.Errorf("only wrote %d bytes to %s; expected %d", n, abs, f.Size)
			}
			if !f.ModTime.IsZero() {
				if err := os.Chtimes(abs, f.ModTime, f.ModTime); err != nil {
					// benign error. Gerrit doesn't even set the
					// modtime in these, and we don't end up relying
					// on it anywhere (the gomote push command relies
					// on digests only), so this is a little pointless
					// for now.
					log.Printf("error changing modtime: %v", err)
				}
			}
		case mode.IsDir():
			if err := os.MkdirAll(abs, 0755); err != nil {
				return err
			}
			madeDir[abs] = true
		default:
			return fmt.Errorf("tar file entry %s contained unsupported file type %v", f.Name, mode)
		}
	}
	return nil
}

// unpackZip is the zip implementation of unpackArchive.
func unpackZip(targetDir, archiveFile string) error {
	zr, err := zip.OpenReader(archiveFile)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		name := strings.TrimPrefix(f.Name, "go/")
		outpath := filepath.Join(targetDir, name)
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(outpath, 0755); err != nil {
				return err
			}
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		// File
		if err := os.MkdirAll(filepath.Dir(outpath), 0755); err != nil {
			return err
		}
		out, err := os.OpenFile(outpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}
		_, err = io.Copy(out, rc)
		rc.Close()
		if err != nil {
			out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
	}
	return nil
}

// verifySHA256 reports whether the named file has contents with
// SHA-256 of the given wantHex value.
func verifySHA256(file, wantHex string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return err
	}
	if fmt.Sprintf("%x", hash.Sum(nil)) != wantHex {
		return fmt.Errorf("%s corrupt? does not have expected SHA-256 of %v", file, wantHex)
	}
	return nil
}

func validRelPath(p string) bool {
	if p == "" || strings.Contains(p, `\`) || strings.HasPrefix(p, "/") || strings.Contains(p, "../") {
		return false
	}
	return true
}

type userAgentTransport struct {
	rt http.RoundTripper
}

func (uat userAgentTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	version := runtime.Version()
	if strings.Contains(version, "devel") {
		// Strip the SHA hash and date. We don't want spaces or other tokens (see RFC2616 14.43)
		version = "devel"
	}
	r.Header.Set("User-Agent", "golang-x-build-version/"+version)
	return uat.rt.RoundTrip(r)
}
