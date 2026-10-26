package slide

import (
	"crypto/sha256"
	"image"
	"image/color"
	"image/draw"
	"math"
	"math/rand/v2"
)

type scene struct {
	background []byte
	tile       []byte
	x, y       int
	tol        int
}

// renderScene draws a procedural background, cuts a notch and extracts the
// piece. No photo assets: the images are generated, deterministic given a seed,
// and free of licensing constraints.
func renderScene(seed [8]byte, width, height, piece int) scene {
	best := drawScene(seed, width, height, piece)
	for i := 0; i < 3 && contrast(best.img, best.x, best.y, piece) < 12; i++ {
		seed = nextSeed(seed)
		best = drawScene(seed, width, height, piece)
	}
	return scene{
		background: best.background,
		tile:       best.tile,
		x:          best.x,
		y:          best.y,
		tol:        best.tol,
	}
}

type drawn struct {
	img        *image.RGBA
	background []byte
	tile       []byte
	x, y, tol  int
}

func drawScene(seed [8]byte, width, height, piece int) drawn {
	rng := rand.New(rand.NewChaCha8(expandSeed(seed)))
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	drawBackground(rng, img)
	drawShapes(rng, img)

	tol := piece * 8 / 100
	if tol < 4 {
		tol = 4
	}
	x := 8 + piece + rng.IntN(max(1, width-2*piece-16))
	y := 8 + rng.IntN(max(1, height-piece-16))

	tileImg := image.NewRGBA(image.Rect(0, 0, piece, piece))
	draw.Draw(tileImg, tileImg.Bounds(), img, image.Pt(x, y), draw.Src)
	drawRim(tileImg)
	tilePNG, err := encodePNG(tileImg)
	if err != nil {
		tilePNG = nil
	}

	drawNotch(img, x, y, piece)
	// The notch is drawn after the piece is extracted, so the tile matches the
	// background but carries no rim from the hole.
	bgPNG, err := encodePNG(img)
	if err != nil {
		bgPNG = nil
	}
	return drawn{img: img, background: bgPNG, tile: tilePNG, x: x, y: y, tol: tol}
}

func drawBackground(rng *rand.Rand, img *image.RGBA) {
	b := img.Bounds()
	top := color.RGBA{
		R: uint8(30 + rng.IntN(120)),
		G: uint8(30 + rng.IntN(120)),
		B: uint8(40 + rng.IntN(140)),
		A: 255,
	}
	bottom := color.RGBA{
		R: uint8(30 + rng.IntN(120)),
		G: uint8(30 + rng.IntN(120)),
		B: uint8(40 + rng.IntN(140)),
		A: 255,
	}
	for y := b.Min.Y; y < b.Max.Y; y++ {
		t := float64(y-b.Min.Y) / float64(max(1, b.Dy()-1))
		c := color.RGBA{
			R: uint8(float64(top.R)*(1-t) + float64(bottom.R)*t),
			G: uint8(float64(top.G)*(1-t) + float64(bottom.G)*t),
			B: uint8(float64(top.B)*(1-t) + float64(bottom.B)*t),
			A: 255,
		}
		for x := b.Min.X; x < b.Max.X; x++ {
			img.SetRGBA(x, y, c)
		}
	}
}

// drawShapes adds 24-48 translucent shapes so that edges exist everywhere but
// no region is flat enough to hide a notch.
func drawShapes(rng *rand.Rand, img *image.RGBA) {
	b := img.Bounds()
	count := 24 + rng.IntN(25)
	for i := 0; i < count; i++ {
		cx := rng.IntN(b.Dx())
		cy := rng.IntN(b.Dy())
		r := 12 + rng.IntN(48)
		c := color.RGBA{
			R: uint8(rng.IntN(256)),
			G: uint8(rng.IntN(256)),
			B: uint8(rng.IntN(256)),
			A: uint8(40 + rng.IntN(70)),
		}
		fillCircle(img, cx, cy, r, c)
	}
}

func fillCircle(img *image.RGBA, cx, cy, r int, c color.RGBA) {
	b := img.Bounds()
	for y := max(b.Min.Y, cy-r); y < min(b.Max.Y, cy+r); y++ {
		dy := y - cy
		half := int(math.Sqrt(float64(r*r - dy*dy)))
		for x := max(b.Min.X, cx-half); x < min(b.Max.X, cx+half); x++ {
			blend(img, x, y, c)
		}
	}
}

func blend(img *image.RGBA, x, y int, c color.RGBA) {
	dst := img.RGBAAt(x, y)
	a := float64(c.A) / 255
	img.SetRGBA(x, y, color.RGBA{
		R: uint8(float64(c.R)*a + float64(dst.R)*(1-a)),
		G: uint8(float64(c.G)*a + float64(dst.G)*(1-a)),
		B: uint8(float64(c.B)*a + float64(dst.B)*(1-a)),
		A: 255,
	})
}

func drawNotch(img *image.RGBA, x, y, piece int) {
	for py := y; py < y+piece; py++ {
		for px := x; px < x+piece; px++ {
			dst := img.RGBAAt(px, py)
			img.SetRGBA(px, py, color.RGBA{
				R: uint8(float64(dst.R) * 0.45),
				G: uint8(float64(dst.G) * 0.45),
				B: uint8(float64(dst.B) * 0.45),
				A: 255,
			})
		}
	}
	rim := color.RGBA{R: 245, G: 245, B: 250, A: 200}
	for i := 0; i < 2; i++ {
		for px := x + i; px < x+piece-i; px++ {
			blend(img, px, y+i, rim)
			blend(img, px, y+piece-1-i, rim)
		}
		for py := y + i; py < y+piece-i; py++ {
			blend(img, x+i, py, rim)
			blend(img, x+piece-1-i, py, rim)
		}
	}
}

func drawRim(img *image.RGBA) {
	b := img.Bounds()
	rim := color.RGBA{R: 255, G: 255, B: 255, A: 220}
	for x := b.Min.X; x < b.Max.X; x++ {
		blend(img, x, b.Min.Y, rim)
		blend(img, x, b.Max.Y-1, rim)
	}
	for y := b.Min.Y; y < b.Max.Y; y++ {
		blend(img, b.Min.X, y, rim)
		blend(img, b.Max.X-1, y, rim)
	}
}

// contrast is the luma spread around a region; low contrast makes the notch
// impossible to see, so the scene is re-rolled.
func contrast(img *image.RGBA, x, y, piece int) float64 {
	var sum, sumSq float64
	var n float64
	for py := y; py < y+piece; py++ {
		for px := x; px < x+piece; px++ {
			if !image.Pt(px, py).In(img.Bounds()) {
				continue
			}
			c := img.RGBAAt(px, py)
			l := 0.299*float64(c.R) + 0.587*float64(c.G) + 0.114*float64(c.B)
			sum += l
			sumSq += l * l
			n++
		}
	}
	if n == 0 {
		return 0
	}
	mean := sum / n
	variance := sumSq/n - mean*mean
	if variance < 0 {
		variance = 0
	}
	return math.Sqrt(variance)
}

func expandSeed(seed [8]byte) [32]byte {
	return sha256.Sum256(seed[:])
}

func nextSeed(seed [8]byte) [8]byte {
	sum := sha256.Sum256(seed[:])
	var out [8]byte
	copy(out[:], sum[:8])
	return out
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
