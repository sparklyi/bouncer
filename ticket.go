package bouncer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
)

// Ticket wire format:
//
//	"b1." + base64url(header || nonce || ciphertext+tag)
//	header  = ver(1) || kid(2) || typeLen(1) || type
//	payload = ver(1) || degree(1) || issuedAt(8) || expiresAt(8) ||
//	          subLen(1) || subject || jti(16) || stateLen(2) || state
//
// The header is the AEAD additional data, so a token cannot be moved to a
// different challenge type without failing authentication.
const (
	tokenPrefix   = "b1."
	tokenVersion  = 1
	keyLen        = 32
	nonceLen      = 12
	jtiLen        = 16
	headerMinSize = 4
)

type keyEntry struct {
	kid  [2]byte
	aead cipher.AEAD
}

type keyring struct {
	entries []keyEntry
	active  int
	byKid   map[[2]byte][]int
}

func newKeyring(secret []byte, previous [][]byte) (*keyring, error) {
	if len(secret) < keyLen {
		return nil, ErrNoSecret
	}
	all := append([][]byte{secret}, previous...)
	kr := &keyring{byKid: make(map[[2]byte][]int, len(all))}
	for i, material := range all {
		if len(material) < keyLen {
			return nil, fmt.Errorf("%w: previous key %d", ErrNoSecret, i)
		}
		key, err := hkdf.Key(sha256.New, material, []byte("bouncer.v1"), "token-aead", keyLen)
		if err != nil {
			return nil, fmt.Errorf("bouncer: derive key: %w", err)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("bouncer: cipher: %w", err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("bouncer: aead: %w", err)
		}
		sum := sha256.Sum256(key)
		kid := [2]byte{sum[0], sum[1]}
		kr.entries = append(kr.entries, keyEntry{kid: kid, aead: aead})
		kr.byKid[kid] = append(kr.byKid[kid], len(kr.entries)-1)
	}
	return kr, nil
}

type payload struct {
	degree    uint8
	issuedAt  int64
	expiresAt int64
	subject   string
	jti       [jtiLen]byte
	state     []byte
}

func (p *payload) encode() ([]byte, error) {
	if len(p.subject) > maxSubject {
		return nil, fmt.Errorf("bouncer: subject too long")
	}
	if len(p.state) > maxState {
		return nil, fmt.Errorf("bouncer: state too long")
	}
	buf := make([]byte, 0, 1+1+8+8+1+len(p.subject)+jtiLen+2+len(p.state))
	buf = append(buf, tokenVersion, p.degree)
	buf = binary.BigEndian.AppendUint64(buf, uint64(p.issuedAt))
	buf = binary.BigEndian.AppendUint64(buf, uint64(p.expiresAt))
	buf = append(buf, byte(len(p.subject)))
	buf = append(buf, p.subject...)
	buf = append(buf, p.jti[:]...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(p.state)))
	return append(buf, p.state...), nil
}

func decodePayload(buf []byte) (payload, error) {
	var p payload
	const fixed = 1 + 1 + 8 + 8 + 1 + jtiLen + 2
	if len(buf) < fixed {
		return p, ErrMalformed
	}
	pos := 0
	if buf[pos] != tokenVersion {
		return p, ErrMalformed
	}
	pos++
	p.degree = buf[pos]
	pos++
	p.issuedAt = int64(binary.BigEndian.Uint64(buf[pos:]))
	pos += 8
	p.expiresAt = int64(binary.BigEndian.Uint64(buf[pos:]))
	pos += 8
	subLen := int(buf[pos])
	pos++
	if subLen > maxSubject || len(buf) < pos+subLen+jtiLen+2 {
		return p, ErrMalformed
	}
	p.subject = string(buf[pos : pos+subLen])
	pos += subLen
	copy(p.jti[:], buf[pos:pos+jtiLen])
	pos += jtiLen
	stateLen := int(binary.BigEndian.Uint16(buf[pos:]))
	pos += 2
	if stateLen > maxState || len(buf) != pos+stateLen {
		return p, ErrMalformed
	}
	p.state = buf[pos:]
	return p, nil
}

func (kr *keyring) seal(typ string, p payload) (string, error) {
	if len(typ) == 0 || len(typ) > 64 {
		return "", fmt.Errorf("bouncer: invalid challenge type")
	}
	plain, err := p.encode()
	if err != nil {
		return "", err
	}
	entry := kr.entries[kr.active]
	header := make([]byte, 0, headerMinSize+len(typ))
	header = append(header, tokenVersion, entry.kid[0], entry.kid[1], byte(len(typ)))
	header = append(header, typ...)

	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("bouncer: nonce: %w", err)
	}
	out := make([]byte, 0, len(header)+nonceLen+len(plain)+16)
	out = append(out, header...)
	out = append(out, nonce...)
	out = entry.aead.Seal(out, nonce, plain, header)
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(out), nil
}

func (kr *keyring) open(token string) (string, payload, error) {
	var p payload
	if len(token) > maxToken || !strings.HasPrefix(token, tokenPrefix) {
		return "", p, ErrMalformed
	}
	raw, err := base64.RawURLEncoding.DecodeString(token[len(tokenPrefix):])
	if err != nil {
		return "", p, ErrMalformed
	}
	if len(raw) < headerMinSize+nonceLen {
		return "", p, ErrMalformed
	}
	if raw[0] != tokenVersion {
		return "", p, ErrMalformed
	}
	kid := [2]byte{raw[1], raw[2]}
	typeLen := int(raw[3])
	headerLen := headerMinSize + typeLen
	if typeLen == 0 || typeLen > 64 || len(raw) < headerLen+nonceLen {
		return "", p, ErrMalformed
	}
	header := raw[:headerLen]
	typ := string(raw[headerMinSize:headerLen])
	nonce := raw[headerLen : headerLen+nonceLen]
	ciphertext := raw[headerLen+nonceLen:]

	candidates := kr.byKid[kid]
	if len(candidates) == 0 {
		// A kid is a hint, not an identity: fall back to every key.
		candidates = make([]int, len(kr.entries))
		for i := range kr.entries {
			candidates[i] = i
		}
	}
	for _, idx := range candidates {
		plain, err := kr.entries[idx].aead.Open(nil, nonce, ciphertext, header)
		if err != nil {
			continue
		}
		p, err := decodePayload(plain)
		if err != nil {
			return "", p, err
		}
		return typ, p, nil
	}
	return "", p, ErrBadToken
}

func randomJTI() ([jtiLen]byte, error) {
	var id [jtiLen]byte
	if _, err := rand.Read(id[:]); err != nil {
		return id, fmt.Errorf("bouncer: jti: %w", err)
	}
	return id, nil
}
