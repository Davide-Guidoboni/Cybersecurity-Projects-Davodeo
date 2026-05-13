// ©AngelaMos | 2026
// types.go

package token

type TypeDescriptor struct {
	Type         Type   `json:"type"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	ArtifactKind string `json:"artifact_kind"`
}

func TypeDescriptors() []TypeDescriptor {
	return []TypeDescriptor{
		{
			Type:         TypeWebbug,
			Name:         "Web Bug Pixel",
			Description:  "1x1 transparent GIF that fires when fetched. Embed in HTML emails or web pages.",
			ArtifactKind: string(KindURL),
		},
		{
			Type:         TypeSlowRedirect,
			Name:         "Slow Redirect",
			Description:  "Browser-fingerprinting page that redirects to a destination URL after collecting client metadata.",
			ArtifactKind: string(KindURL),
		},
		{
			Type:         TypeDocx,
			Name:         "Microsoft Word Document",
			Description:  "DOCX with an embedded INCLUDEPICTURE field that calls home when the document opens.",
			ArtifactKind: string(KindFile),
		},
		{
			Type:         TypePDF,
			Name:         "PDF Document",
			Description:  "PDF with an /AA open-action URI that fires in Adobe Acrobat Reader.",
			ArtifactKind: string(KindFile),
		},
		{
			Type:         TypeKubeconfig,
			Name:         "Kubernetes Config",
			Description:  "kubeconfig pointing kubectl at a fake K8s API server that records every request.",
			ArtifactKind: string(KindText),
		},
		{
			Type:         TypeEnvfile,
			Name:         ".env File",
			Description:  "Plausible production .env with shuffled bait credentials and an embedded canary URL.",
			ArtifactKind: string(KindText),
		},
		{
			Type:         TypeMySQL,
			Name:         "MySQL Connection String",
			Description:  "Fake MySQL endpoint that records any authentication attempt.",
			ArtifactKind: string(KindConnectionString),
		},
	}
}
