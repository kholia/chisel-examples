package main

// This hack uses code from:
// - https://github.com/aquasecurity/trivy

import (
	"bufio"
	"crypto/sha1" // nolint
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/mitchellh/hashstructure/v2"
	"github.com/samber/lo"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"
	"pault.ag/go/debian/deb"
)

type Algorithm string

func (a Algorithm) String() string {
	return string(a)
}

// supported digest types
const (
	SHA1   Algorithm = "sha1"   // sha1 with hex encoding (lower case only)
	SHA256 Algorithm = "sha256" // sha256 with hex encoding (lower case only)
	MD5    Algorithm = "md5"    // md5 with hex encoding (lower case only)
)

// Digest allows simple protection of hex formatted digest strings, prefixed by their algorithm.
//
// The following is an example of the contents of Digest types:
//
//	sha256:7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc
type Digest string

// NewDigest returns a Digest from alg and a hash.Hash object.
func NewDigest(alg Algorithm, h hash.Hash) Digest {
	return Digest(fmt.Sprintf("%s:%x", alg, h.Sum(nil)))
}

// NewDigestFromString returns a Digest from alg and a string.
func NewDigestFromString(alg Algorithm, h string) Digest {
	return Digest(fmt.Sprintf("%s:%s", alg, h))
}

func (d Digest) Algorithm() Algorithm {
	return Algorithm(d[:d.sepIndex()])
}

func (d Digest) Encoded() string {
	return string(d[d.sepIndex()+1:])
}

func (d Digest) String() string {
	return string(d)
}

func (d Digest) sepIndex() int {
	i := strings.Index(string(d), ":")
	if i < 0 {
		i = 0
	}
	return i
}

func CalcSHA1(r io.ReadSeeker) (Digest, error) {
	defer r.Seek(0, io.SeekStart)

	h := sha1.New() // nolint
	if _, err := io.Copy(h, r); err != nil {
		return "", xerrors.Errorf("unable to calculate sha1 digest: %w", err)
	}

	return NewDigest(SHA1, h), nil
}

func CalcSHA256(r io.ReadSeeker) (Digest, error) {
	defer r.Seek(0, io.SeekStart)

	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", xerrors.Errorf("unable to calculate sha256 digest: %w", err)
	}

	return NewDigest(SHA256, h), nil
}

type Location struct {
	StartLine int `json:",omitempty"`
	EndLine   int `json:",omitempty"`
}

// BuildInfo represents information under /root/buildinfo in RHEL
type BuildInfo struct {
	ContentSets []string `json:",omitempty"`
	Nvr         string   `json:",omitempty"`
	Arch        string   `json:",omitempty"`
}

type Repository struct {
	Family  string `json:",omitempty"`
	Release string `json:",omitempty"`
}

type Layer struct {
	Digest    string `json:",omitempty"`
	DiffID    string `json:",omitempty"`
	CreatedBy string `json:",omitempty"`
}

type Package struct {
	ID         string   `json:",omitempty"`
	Name       string   `json:",omitempty"`
	Version    string   `json:",omitempty"`
	Release    string   `json:",omitempty"`
	Epoch      int      `json:",omitempty"`
	Arch       string   `json:",omitempty"`
	SrcName    string   `json:",omitempty"`
	SrcVersion string   `json:",omitempty"`
	SrcRelease string   `json:",omitempty"`
	SrcEpoch   int      `json:",omitempty"`
	Licenses   []string `json:",omitempty"`
	Maintainer string   `json:",omitempty"`

	Modularitylabel string     `json:",omitempty"` // only for Red Hat based distributions
	BuildInfo       *BuildInfo `json:",omitempty"` // only for Red Hat

	Ref      string `json:",omitempty"` // identifier which can be used to reference the component elsewhere
	Indirect bool   `json:",omitempty"` // this package is direct dependency of the project or not

	// Dependencies of this package
	// Note:　it may have interdependencies, which may lead to infinite loops.
	DependsOn []string `json:",omitempty"`

	Layer Layer `json:",omitempty"`

	// Each package metadata have the file path, while the package from lock files does not have.
	FilePath string `json:",omitempty"`

	// This is required when using SPDX formats. Otherwise, it will be empty.
	Digest Digest `json:",omitempty"`

	// lines from the lock file where the dependency is written
	Locations []Location `json:",omitempty"`
}

var (
	dpkgLicenseAnalyzerVersion = 1

	commonLicenseReferenceRegexp = regexp.MustCompile(`/?usr/share/common-licenses/([0-9A-Za-z_.+-]+[0-9A-Za-z+])`)
	licenseSplitRegexp           = regexp.MustCompile("(,?[_ ]+or[_ ]+)|(,?[_ ]+and[_ ])|(,[ ]*)")
)

// dpkgLicenseAnalyzer parses copyright files and detect licenses
type dpkgLicenseAnalyzer struct {
	licenseFull               bool
	classifierConfidenceLevel float64
}

type LicenseType string

const (
	LicenseTypeDpkg   LicenseType = "dpkg"         // From /usr/share/doc/*/copyright
	LicenseTypeHeader LicenseType = "header"       // From file headers
	LicenseTypeFile   LicenseType = "license-file" // From LICENSE, COPYRIGHT, etc.
)

type LicenseCategory string

const (
	CategoryForbidden    LicenseCategory = "forbidden"
	CategoryRestricted   LicenseCategory = "restricted"
	CategoryReciprocal   LicenseCategory = "reciprocal"
	CategoryNotice       LicenseCategory = "notice"
	CategoryPermissive   LicenseCategory = "permissive"
	CategoryUnencumbered LicenseCategory = "unencumbered"
	CategoryUnknown      LicenseCategory = "unknown"
)

type LicenseFile struct {
	Type     LicenseType
	FilePath string
	PkgName  string
	Findings LicenseFindings
	Layer    Layer `json:",omitempty"`
}

type LicenseFindings []LicenseFinding

func (findings LicenseFindings) Len() int {
	return len(findings)
}

func (findings LicenseFindings) Swap(i, j int) {
	findings[i], findings[j] = findings[j], findings[i]
}

func (findings LicenseFindings) Less(i, j int) bool {
	return findings[i].Name < findings[j].Name
}

type LicenseFinding struct {
	Category   LicenseCategory // such as "forbidden"
	Name       string
	Confidence float64
	Link       string
}

// Analyze parses /usr/share/doc/*/copyright files
// parseCopyright parses /usr/share/doc/*/copyright files
func parseCopyright(r string) ([]LicenseFinding, error) {
	scanner := bufio.NewScanner(strings.NewReader(r))
	var licenses []string
	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case strings.HasPrefix(line, "License:"):
			// Machine-readable format
			// cf. https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/#:~:text=The%20debian%2Fcopyright%20file%20must,in%20the%20Debian%20Policy%20Manual.
			l := strings.TrimSpace(line[8:])
			l = normalizeLicense(l)
			if len(l) > 0 {
				// Split licenses without considering "and"/"or"
				// examples:
				// 'GPL-1+,GPL-2' => {"GPL-1", "GPL-2"}
				// 'GPL-1+ or Artistic or Artistic-dist' => {"GPL-1", "Artistic", "Artistic-dist"}
				// 'LGPLv3+_or_GPLv2+' => {"LGPLv3", "GPLv2"}
				// 'BSD-3-CLAUSE and GPL-2' => {"BSD-3-CLAUSE", "GPL-2"}
				// 'GPL-1+ or Artistic, and BSD-4-clause-POWERDOG' => {"GPL-1+", "Artistic", "BSD-4-clause-POWERDOG"}
				for _, lic := range licenseSplitRegexp.Split(l, -1) {
					lic = normalizeLicense(lic)
					if !slices.Contains(licenses, lic) {
						licenses = append(licenses, lic)
					}
				}
			}
		case strings.Contains(line, "/usr/share/common-licenses/"):
			// Common license pattern
			license := commonLicenseReferenceRegexp.FindStringSubmatch(line)
			if len(license) == 2 {
				l := normalizeLicense(license[1])
				if !slices.Contains(licenses, l) {
					licenses = append(licenses, l)
				}
			}
		}
	}

	return lo.Map(licenses, func(license string, _ int) LicenseFinding {
		return LicenseFinding{Name: license}
	}), nil

}

// normalizeLicense returns a normalized license identifier in a heuristic way
func normalizeLicense(s string) string {
	// "The MIT License (MIT)" => "The MIT License"
	s, _, _ = strings.Cut(s, "(")

	// Very rarely has below phrases
	s = strings.TrimPrefix(s, "The main library is licensed under ")
	s = strings.TrimSuffix(s, " license")

	return strings.TrimSpace(s)
}

func main() {
	path := os.Args[1]
	fd, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer fd.Close()

	debFile, err := deb.Load(fd, path)
	if err != nil {
		panic(err)
	}

	// Fill in the metadata - https://pkg.go.dev/pault.ag/go/debian@v0.15.0/deb#Control
	c := debFile.Control
	p := Package{Name: c.Package}
	p.Version = c.Version.Version
	p.ID = fmt.Sprintf("%s@%s", p.Name, c.Version.String())
	p.Release = c.Version.Revision
	p.Epoch = (int)(c.Version.Epoch)
	p.Arch = c.Architecture.String()
	p.SrcName = p.Name
	p.SrcVersion = p.Version
	p.SrcRelease = p.Release
	p.SrcEpoch = p.Epoch
	p.Maintainer = c.Maintainer
	/* Canonicalize c.Depends.String() */
	depends := strings.Split(c.Depends.String(), ", ")
	odepends := depends
	for i := 0; i < len(depends); i++ {
		odepends[i] = strings.Split(depends[i], " ")[0]
	}
	p.DependsOn = odepends
	// Licensing stuff (this is perhaps a bug / misfeature in Trivy)
	tr := debFile.Data
	copyright := ""
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		if strings.HasSuffix(hdr.Name, "copyright") {
			bs, _ := ioutil.ReadAll(tr)
			copyright = string(bs)
		}
	}

	if copyright != "" {
		licenses, _ := parseCopyright(copyright)
		olicenses := []string{}
		for i := 0; i < len(licenses); i++ {
			if !strings.Contains(licenses[i].Name, "+") {
				olicenses = append(olicenses, licenses[i].Name)
			}
		}
		fmt.Println(olicenses)
		p.Licenses = olicenses

	}
	fmt.Println(p)

	/* Hash 'p': */
	hash, err := hashstructure.Hash(p, hashstructure.FormatV2, nil)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%x\n", hash)

}
