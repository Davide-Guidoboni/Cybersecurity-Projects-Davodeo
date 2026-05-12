// ©AngelaMos | 2026
// pixel_test.go

package pixel_test

import (
	"bytes"
	"image/gif"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/pixel"
)

const (
	expectedLength = 43
	expectedWidth  = 1
	expectedHeight = 1
)

var (
	gif89aMagic = []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}
	gifTrailer  = byte(0x3b)
)

func TestLen_Is43(t *testing.T) {
	require.Equal(t, expectedLength, pixel.Len())
}

func TestClone_Length(t *testing.T) {
	require.Len(t, pixel.Clone(), expectedLength)
}

func TestClone_MagicBytes(t *testing.T) {
	g := pixel.Clone()
	require.True(
		t,
		bytes.HasPrefix(g, gif89aMagic),
		"expected GIF89a magic prefix, got % x",
		g[:len(gif89aMagic)],
	)
	require.Equal(
		t,
		gifTrailer,
		g[len(g)-1],
		"expected trailing GIF terminator 0x3B",
	)
}

func TestClone_DecodesAsImageGIF(t *testing.T) {
	img, err := gif.Decode(bytes.NewReader(pixel.Clone()))
	require.NoError(t, err)
	require.NotNil(t, img)

	bounds := img.Bounds()
	require.Equal(t, expectedWidth, bounds.Dx())
	require.Equal(t, expectedHeight, bounds.Dy())
}

func TestClone_ReturnsIndependentCopy(t *testing.T) {
	a := pixel.Clone()
	b := pixel.Clone()
	require.Equal(t, a, b, "two clones must be byte-equal")

	a[0] = 0x00
	require.Equal(
		t,
		byte(0x47),
		b[0],
		"mutating one clone must not affect another",
	)
	require.Equal(
		t,
		byte(0x47),
		pixel.Clone()[0],
		"mutating one clone must not affect the package-internal source",
	)
}

func TestContentType_IsImageGIF(t *testing.T) {
	require.Equal(t, "image/gif", pixel.ContentType)
}
