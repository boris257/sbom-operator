package trivy

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
	"k8s.io/apimachinery/pkg/util/json"

	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-operator/pkg/oci"
	"github.com/sirupsen/logrus"
)

type Trivy struct {
	sbomFormat       string
	resolveVersion   func() string
	proxyRegistryMap map[string]string
}

func New(sbomFormat string, proxyRegistryMap map[string]string) *Trivy {
	return &Trivy{
		sbomFormat:       sbomFormat,
		resolveVersion:   getTrivyVersion,
		proxyRegistryMap: proxyRegistryMap,
	}
}

func (s Trivy) WithVersion(version string) Trivy {
	s.resolveVersion = func() string { return version }
	return s
}

func (s *Trivy) ExecuteTrivy(img *oci.RegistryImage) (string, error) {
	logrus.Infof("Processing image %s", img.Image)
	err := kubernetes.ApplyProxyRegistry(img, true, s.proxyRegistryMap)
	if err != nil {
		return "", err
	}

	var output bytes.Buffer
	trivyOptions := flag.Options{
		GlobalOptions: flag.GlobalOptions{
			Timeout:  10 * time.Minute,
			CacheDir: utils.DefaultCacheDir(),
		},
		ScanOptions: flag.ScanOptions{
			Target:         img.Image,
			SecurityChecks: nil, // Disable all security checks for SBOM only scan
		},
		ReportOptions: flag.ReportOptions{
			Format:       "cyclonedx", // Cyconedx format for SBOM so that we don't need to convert
			ReportFormat: "all",       // Full report not just summary
			Output:       &output,     // Save the output to our local buffer instead of Stdout
			ListAllPkgs:  true,        // By default Trivy only includes packages with vulnerabilities, for full SBOM set true.
		},
		VulnerabilityOptions: flag.VulnerabilityOptions{
			VulnType: types.VulnTypes, // Trivy disables analyzers for language packages if VulnTypeLibrary not in VulnType list
		},
	}

	// Ensure we're configured for private registry if required
	creds := oci.ConvertSecrets(*img, s.proxyRegistryMap)
	for _, cred := range creds {
		if cred.Username != "" {
			os.Setenv("TRIVY_USERNAME", cred.Username)
		}
		if cred.Password != "" {
			os.Setenv("TRIVY_PASSWORD", cred.Password)
		}
		if cred.Token != "" {
			os.Setenv("TRIVY_REGISTRY_TOKEN", cred.Token)
		}
		break
	}

	err = artifact.Run(context.TODO(), trivyOptions, artifact.TargetContainerImage)
	if err != nil {
		return "", fmt.Errorf("failed to generate SBOM: %w", err)
	}

	// Decode the BOM
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(&output, cdx.BOMFileFormatJSON)
	if err = decoder.Decode(bom); err != nil {
		return "", fmt.Errorf("unable to decode BOM data: %v", err)
	}

	data, err := json.Marshal(bom)
	if err != nil {
		return "", fmt.Errorf("unable to encode BOM data: %v", err)
	}

	return string(data), nil
}

func GetFileName(sbomFormat string) string {
	switch sbomFormat {
	case "json", "trivyjson", "cyclonedxjson", "spdxjson", "github", "githubjson":
		return "sbom.json"
	case "cyclonedx", "cyclone", "cyclonedxxml":
		return "sbom.xml"
	case "spdx", "spdxtv", "spdxtagvalue":
		return "sbom.spdx"
	case "text":
		return "sbom.txt"
	case "table":
		return "sbom.txt"
	default:
		return "sbom.json"
	}
}

func getTrivyVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		logrus.Warnf("failed to read build info")
	}

	for _, dep := range bi.Deps {
		if strings.EqualFold("github.com/aquasecurity/trivy", dep.Path) {
			return dep.Version
		}
	}

	return ""
}
