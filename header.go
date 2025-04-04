package p2pdf

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/XzZZzX02/p2pdfs/crypto"
)

// Header represents a collection of header fields.
type Header []HeaderField

// HeaderField represents a single header field with a name and value.
type HeaderField struct {
	Name  string // Name of the header field
	Value []byte // Value of the header field
}

const (
	MaxHeaderNameLength  = 256
	MaxHeaderValueLength = 10 * 1024 // 10 KiB
)

const (
	headerNameCharset       = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_."
	headerBinaryValuePrefix = "b64,"
	headerTextValueCharset  = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_.,:;+=?~!@#$%^&*()<>[]{}/| "
)

var errInvalidJSON = errors.New("invalid JSON")

// predefined header-field-names
const (
	// root header fields
	headerProtocol  = "Protocol"   //
	headerPublicKey = "Public-Key" //
	headerSignature = "Signature"  //
	headerVolume    = "Volume"     // volume of full file tree

	// general
	headerVer        = "Ver"     // File or directory version
	headerPath       = "Path"    // File or directory path
	headerCreated    = "Created" // Creation time
	headerUpdated    = "Updated" // Update time
	headerDeleted    = "Deleted" // Deleted flag
	headerMerkleHash = "Merkle"  // Content hash (Merkle root)

	// files
	headerFileSize     = "Size"      // File size
	headerFilePartSize = "Part-Size" // File part size
)

// NewHeader creates a new header with the given path.
func NewHeader(path string) (h Header) {
	h.SetPath(path)
	return
}

// NewRootHeader creates a new root header with the given public key.
func NewRootHeader(pub crypto.PublicKey) (h Header) {
	h.Add(headerProtocol, DefaultProtocol)
	h.AddInt(headerVer, 0)
	h.AddInt(headerFilePartSize, DefaultFilePartSize)
	h.SetPublicKey(pub)
	return
}

// Copy returns a copy of the header.
func (h Header) Copy() Header {
	h1 := make(Header, len(h))
	copy(h1, h)
	return h1
}

// String returns the header as a JSON string.
func (h Header) String() string {
	s, _ := h.MarshalJSON()
	return string(s)
}

// MarshalJSON implements json.Marshaler.
func (h Header) MarshalJSON() ([]byte, error) {
	buf := bytes.NewBufferString("{")
	for i, v := range h {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteByte('"')
		buf.WriteString(v.Name) // key (does not contain special characters)
		buf.WriteByte('"')
		buf.WriteByte(':')
		jsonMarshalValue(buf, v.Value)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (h *Header) UnmarshalJSON(data []byte) (err error) {
	n := len(data)
	if n < 2 || data[0] != '{' || data[n-1] != '}' {
		return errInvalidJSON
	}
	// replace object to array:  {"key":"value",...} -> ["key","value",...]
	data = bytes.ReplaceAll(data, []byte(`":"`), []byte(`","`))
	data[0], data[n-1] = '[', ']'
	var ss []string
	if err = json.Unmarshal(data, &ss); err != nil {
		return
	}
	*h = (*h)[:0]
	var kv HeaderField
	for i, v := range ss {
		if i%2 == 0 { // key
			kv.Name = v
		} else { // value
			if kv.Value, err = jsonUnmarshalValue(v); err != nil {
				return err
			}
			*h = append(*h, kv)
		}
	}
	return
}

// MarshalText implements encoding.TextMarshaler.
func (h Header) MarshalText() ([]byte, error) {
	buf := bytes.NewBufferString(``)
	for _, v := range h {
		buf.WriteString(v.Name)
		buf.WriteString(": ")
		textMarshalValue(buf, v.Value)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

// jsonMarshalValue writes a JSON value to the buffer.
func jsonMarshalValue(buf *bytes.Buffer, v []byte) {
	buf.WriteByte('"')
	textMarshalValue(buf, v)
	buf.WriteByte('"')
}

// textMarshalValue writes a text value to the buffer.
func textMarshalValue(buf *bytes.Buffer, v []byte) {
	if containsOnly(v, headerTextValueCharset) && !bytes.HasPrefix(v, []byte(headerBinaryValuePrefix)) {
		buf.Write(v)
	} else {
		buf.WriteString(headerBinaryValuePrefix)
		buf.WriteString(base64.RawStdEncoding.EncodeToString(v))
	}
}

// jsonUnmarshalValue unmarshals a header value.
func jsonUnmarshalValue(v string) ([]byte, error) {
	if strings.HasPrefix(v, headerBinaryValuePrefix) {
		return base64.RawStdEncoding.DecodeString(strings.TrimPrefix(v, headerBinaryValuePrefix))
	}
	return []byte(v), nil
}

// indexOf returns the index of the header field with the given key.
func (h Header) indexOf(key string) int {
	for i := len(h) - 1; i >= 0; i-- {
		if h[i].Name == key {
			return i
		}
	}
	return -1
}

// Has checks if the header contains the given key.
func (h Header) Has(key string) bool {
	return h.indexOf(key) >= 0
}

// Get returns the value of the header field with the given key as a string.
func (h Header) Get(key string) string {
	return string(h.GetBytes(key))
}

// GetBytes returns the value of the header field with the given key as a byte slice.
func (h Header) GetBytes(key string) []byte {
	if i := h.indexOf(key); i >= 0 {
		return h[i].Value
	}
	return nil
}

// GetInt returns the value of the header field with the given key as an int64.
func (h Header) GetInt(key string) int64 {
	i, _ := strconv.ParseInt(h.Get(key), 10, 64)
	return i
}

// GetNum returns the value of the header field with the given key as a float64.
func (h Header) GetNum(key string) float64 {
	f, _ := strconv.ParseFloat(h.Get(key), 64)
	return f
}

// GetTime returns the value of the header field with the given key as a time.Time.
func (h Header) GetTime(key string) time.Time {
	t, _ := time.Parse(time.RFC3339, h.Get(key))
	return t
}

// Set sets the value of the header field with the given key to the given string value.
func (h *Header) Set(key, value string) {
	h.SetBytes(key, []byte(value))
}

// SetBytes sets the value of the header field with the given key to the given byte slice.
func (h *Header) SetBytes(key string, value []byte) {
	if i := h.indexOf(key); i >= 0 {
		(*h)[i].Value = value
	} else {
		*h = append(*h, HeaderField{key, value})
	}
}

// SetInt sets the value of the header field with the given key to the given int64 value.
func (h *Header) SetInt(key string, value int64) {
	h.Set(key, strconv.FormatInt(value, 10))
}

// SetTime sets the value of the header field with the given key to the given time.Time value.
func (h *Header) SetTime(key string, value time.Time) {
	h.Set(key, value.Format(time.RFC3339))
}

// Add adds a new header field with the given key and string value.
func (h *Header) Add(key, value string) {
	h.AddBytes(key, []byte(value))
}

// AddBytes adds a new header field with the given key and byte slice value.
func (h *Header) AddBytes(key string, value []byte) {
	*h = append(*h, HeaderField{key, value})
}

// AddInt adds a new header field with the given key and int64 value.
func (h *Header) AddInt(key string, value int64) {
	h.Add(key, strconv.FormatInt(value, 10))
}

// AddNum adds a new header field with the given key and float64 value.
func (h *Header) AddNum(key string, value float64) {
	h.Add(key, fmt.Sprint(value))
}

// AddTime adds a new header field with the given key and time.Time value.
func (h *Header) AddTime(key string, value time.Time) {
	h.Add(key, value.Format(time.RFC3339))
}

// Delete removes all header fields with the given key.
func (h *Header) Delete(key string) {
	for i := h.indexOf(key); i >= 0; i = h.indexOf(key) {
		c := *h
		copy(c[i:], c[i+1:])
		*h = c[:len(c)-1]
	}
}

// Hash returns the hash of the header.
func (h Header) Hash() []byte {
	n := len(h)
	if n > 0 && h[n-1].Name == headerSignature { // exclude last header "Signature"
		n--
	}
	hsh := crypto.NewHash()
	for _, kv := range h[:n-1] {
		// write <len><Name>
		binary.Write(hsh, binary.BigEndian, uint32(len(kv.Name)))
		hsh.Write([]byte(kv.Name))

		// write <len><Value>
		binary.Write(hsh, binary.BigEndian, uint32(len(kv.Value)))
		hsh.Write(kv.Value)
	}
	return hsh.Sum(nil)
}

// Length returns the total length of all header fields.
func (h Header) Length() (n int) {
	for _, kv := range h {
		n += len(kv.Name) + len(kv.Value)
	}
	return
}

// totalVolume returns the total volume of the header.
func (h Header) totalVolume() int64 {
	return int64(h.Length()) + h.FileSize()
}

//--------------------------------------
//        pre-defined params
//--------------------------------------

// Path returns the path of the header.
func (h Header) Path() string {
	return h.Get(headerPath)
}

// SetPath sets the path of the header.
func (h *Header) SetPath(path string) {
	if path == "" {
		h.Delete(headerPath)
	} else {
		h.Set(headerPath, path)
	}
}

// IsRoot checks if the header is the root header.
func (h Header) IsRoot() bool {
	return !h.Has(headerPath)
}

// IsDir checks if the header represents a directory.
func (h Header) IsDir() bool {
	return isDir(h.Path())
}

// IsFile checks if the header represents a file.
func (h Header) IsFile() bool {
	return !h.IsDir()
}

// Deleted checks if the header is marked as deleted.
func (h Header) Deleted() bool {
	return h.Has(headerDeleted)
}

// Ver returns last file, dir or commit-version
func (h Header) Ver() int64 {
	return h.GetInt(headerVer)
}

// PartSize returns the part size of the storage file in bytes.
func (h Header) PartSize() int64 {
	return h.GetInt(headerFilePartSize)
}

// Updated returns the update time of the storage node.
func (h Header) Updated() time.Time {
	return h.GetTime(headerUpdated)
}

// Created returns the creation time of the storage node.
func (h Header) Created() time.Time {
	return h.GetTime(headerCreated)
}

// FileSize returns the file size of the storage file in bytes.
func (h Header) FileSize() int64 {
	return h.GetInt(headerFileSize)
}

// MerkleHash returns the Merkle hash of the header.
func (h Header) MerkleHash() []byte {
	return h.GetBytes(headerMerkleHash)
}

//--------- root-header crypto methods ----------

// Protocol returns the protocol version of the storage.
func (h Header) Protocol() string {
	return h.Get(headerProtocol)
}

// PublicKey returns the public key of the storage.
func (h Header) PublicKey() crypto.PublicKey {
	return crypto.DecodePublicKey(h.Get(headerPublicKey))
}

// SetPublicKey sets the public key of the storage.
func (h *Header) SetPublicKey(pub crypto.PublicKey) {
	h.Set(headerPublicKey, pub.Encode())
}

// Sign signs the header with the given private key.
func (h *Header) Sign(prv crypto.PrivateKey) {
	h.SetPublicKey(prv.PublicKey())

	h.Delete(headerSignature)
	h.AddBytes(headerSignature, prv.Sign(h.Hash()))
}

// Verify verifies the signature of the root-header.
func (h Header) Verify() bool {
	n := len(h)
	return n >= 2 &&
		h[n-1].Name == headerSignature && // last key is "Signature"
		h.PublicKey().Verify(h[:n-1].Hash(), h[n-1].Value)
}

// VerifyMerkleProof verifies the merkle-proof of the header.
func (h Header) VerifyMerkleProof(merkleRoot, proof []byte) bool {
	return crypto.VerifyMerkleProof(h.Hash(), merkleRoot, proof)
}

// ValidateHeader validates header fields.
func ValidateHeader(h Header) error {
	for _, v := range h {
		if !isValidHeaderField(v) {
			return errInvalidHeader
		}
	}
	if h.Has(headerPath) && !IsValidPath(h.Path()) {
		return errInvalidPath
	}
	return nil
}

// isValidHeaderField checks if the header field is valid.
func isValidHeaderField(v HeaderField) bool {
	return len(v.Name) <= MaxHeaderNameLength &&
		len(v.Value) <= MaxHeaderValueLength &&
		containsOnly([]byte(v.Name), headerNameCharset)
}

// sortHeaders sorts the headers by path.
func sortHeaders(hh []Header) {
	sort.Slice(hh, func(i, j int) bool {
		return pathLess(hh[i].Path(), hh[j].Path())
	})
}

// traceHeaders prints the headers for debugging.
func traceHeaders(hh []Header) {
	for _, h := range hh {
		println("  - ", h.String())
	}
	println("")
}

// isDir checks if the path represents a directory.
func isDir(path string) bool {
	return path == "" || path[len(path)-1] == '/' // is root or ended with '/'
}
