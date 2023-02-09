package oci

import "strings"

type KubeCreds struct {
	SecretName      string
	SecretCredsData []byte
	IsLegacySecret  bool
}

type RegistryImage struct {
	ImageID     string
	Image       string
	PullSecrets []*KubeCreds
}

func (r *RegistryImage) Ref() string {
	if strings.HasPrefix(r.Image, "sha256:") {
		return r.ImageID
	}
	return r.Image
}
