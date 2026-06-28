package crypto

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

var (
	sm2P, _  = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	sm2A, _  = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
	sm2B, _  = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	sm2Gx, _ = new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	sm2Gy, _ = new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	sm2N, _  = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
)

type sm2Point struct{ x, y *big.Int }

func newPoint(x, y *big.Int) *sm2Point { return &sm2Point{new(big.Int).Set(x), new(big.Int).Set(y)} }

func (p *sm2Point) Double() *sm2Point {
	if p.y.Sign() == 0 {
		return &sm2Point{new(big.Int), new(big.Int)}
	}
	num := new(big.Int).Mul(p.x, p.x)
	num.Mul(num, big.NewInt(3))
	num.Add(num, sm2A)
	den := new(big.Int).Mul(p.y, big.NewInt(2))
	den.ModInverse(den, sm2P)
	s := new(big.Int).Mul(num, den)
	s.Mod(s, sm2P)
	x3 := new(big.Int).Mul(s, s)
	x3.Sub(x3, p.x)
	x3.Sub(x3, p.x)
	x3.Mod(x3, sm2P)
	y3 := new(big.Int).Sub(p.x, x3)
	y3.Mul(y3, s)
	y3.Sub(y3, p.y)
	y3.Mod(y3, sm2P)
	return &sm2Point{x3, y3}
}

func (p *sm2Point) Add(q *sm2Point) *sm2Point {
	if p.y.Sign() == 0 {
		return newPoint(q.x, q.y)
	}
	if q.y.Sign() == 0 {
		return newPoint(p.x, p.y)
	}
	if p.x.Cmp(q.x) == 0 {
		if p.y.Cmp(q.y) == 0 {
			return p.Double()
		}
		return &sm2Point{new(big.Int), new(big.Int)}
	}
	num := new(big.Int).Sub(q.y, p.y)
	den := new(big.Int).Sub(q.x, p.x)
	den.ModInverse(den, sm2P)
	s := new(big.Int).Mul(num, den)
	s.Mod(s, sm2P)
	x3 := new(big.Int).Mul(s, s)
	x3.Sub(x3, p.x)
	x3.Sub(x3, q.x)
	x3.Mod(x3, sm2P)
	y3 := new(big.Int).Sub(p.x, x3)
	y3.Mul(y3, s)
	y3.Sub(y3, p.y)
	y3.Mod(y3, sm2P)
	return &sm2Point{x3, y3}
}

func scalarMultG(k *big.Int) *sm2Point {
	g := newPoint(sm2Gx, sm2Gy)
	res := &sm2Point{new(big.Int), new(big.Int)}
	for _, b := range k.Bytes() {
		for bit := 7; bit >= 0; bit-- {
			res = res.Double()
			if (b>>uint(bit))&1 == 1 {
				res = res.Add(g)
			}
		}
	}
	return res
}

func GenerateSM2KeyPair() (priv, pubX, pubY []byte, err error) {
	one := big.NewInt(1)
	d, err := rand.Int(rand.Reader, new(big.Int).Sub(sm2N, one))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("rand: %w", err)
	}
	d.Add(d, one)
	p := scalarMultG(d)
	return fixedBytes(d, 32), fixedBytes(p.x, 32), fixedBytes(p.y, 32), nil
}

func publicFromD(d []byte) (pubX, pubY []byte) {
	p := scalarMultG(new(big.Int).SetBytes(d))
	return fixedBytes(p.x, 32), fixedBytes(p.y, 32)
}

func fixedBytes(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) >= size {
		return b[len(b)-size:]
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func onCurve(x, y *big.Int) bool {
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, sm2P)
	rhs := new(big.Int).Exp(x, big.NewInt(3), sm2P)
	ax := new(big.Int).Mul(sm2A, x)
	ax.Mod(ax, sm2P)
	rhs.Add(rhs, ax)
	rhs.Add(rhs, sm2B)
	rhs.Mod(rhs, sm2P)
	return y2.Cmp(rhs) == 0
}
