package proton

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// getEncryptedName encrypts a file/folder name using the provided keyrings.
func getEncryptedName(name string, addrKR, nodeKR *crypto.KeyRing) (string, error) {
	clearTextName := crypto.NewPlainMessageFromString(name)

	encName, err := nodeKR.Encrypt(clearTextName, addrKR)
	if err != nil {
		return "", err
	}

	encNameString, err := encName.GetArmored()
	if err != nil {
		return "", err
	}

	return encNameString, nil
}

// GetNameHash computes the HMAC-SHA256 hash of a name using the provided hash key.
func GetNameHash(name string, hashKey []byte) (string, error) {
	mac := hmac.New(sha256.New, hashKey)
	_, err := mac.Write([]byte(name))
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(mac.Sum(nil)), nil
}

// MoveLinkReq is the request body for moving/renaming a link.
type MoveLinkReq struct {
	ParentLinkID string

	Name                    string // Encrypted File Name
	OriginalHash            string // Old Encrypted File Name Hash
	Hash                    string // Encrypted File Name Hash by using parent's NodeHashKey
	NodePassphrase          string // The passphrase used to unlock the NodeKey, encrypted by the owning Link/Share keyring.
	NodePassphraseSignature string // The signature of the NodePassphrase

	SignatureAddress string // Signature email address used to sign passphrase and name
}

// SetName encrypts and sets the name field.
func (r *MoveLinkReq) SetName(name string, addrKR, nodeKR *crypto.KeyRing) error {
	encNameString, err := getEncryptedName(name, addrKR, nodeKR)
	if err != nil {
		return err
	}

	r.Name = encNameString
	return nil
}

// SetHash computes and sets the hash field.
func (r *MoveLinkReq) SetHash(name string, hashKey []byte) error {
	nameHash, err := GetNameHash(name, hashKey)
	if err != nil {
		return err
	}

	r.Hash = nameHash
	return nil
}

type CreateFileReq struct {
	ParentLinkID string

	Name     string // Encrypted File Name
	Hash     string // Encrypted content hash
	MIMEType string // MIME Type

	ContentKeyPacket          string // The block's key packet, encrypted with the node key.
	ContentKeyPacketSignature string // Unencrypted signature of the content session key, signed with the NodeKey

	NodeKey                 string // The private NodeKey, used to decrypt any file/folder content.
	NodePassphrase          string // The passphrase used to unlock the NodeKey, encrypted by the owning Link/Share keyring.
	NodePassphraseSignature string // The signature of the NodePassphrase

	SignatureAddress string // Signature email address used to sign passphrase and name
}

// SetName encrypts and sets the name field.
func (r *CreateFileReq) SetName(name string, addrKR, nodeKR *crypto.KeyRing) error {
	encNameString, err := getEncryptedName(name, addrKR, nodeKR)
	if err != nil {
		return err
	}

	r.Name = encNameString
	return nil
}

// SetHash computes and sets the hash field.
func (r *CreateFileReq) SetHash(name string, hashKey []byte) error {
	nameHash, err := GetNameHash(name, hashKey)
	if err != nil {
		return err
	}

	r.Hash = nameHash
	return nil
}

// SetContentKeyPacketAndSignature generates a new session key and sets the
// ContentKeyPacket and ContentKeyPacketSignature fields.
func (r *CreateFileReq) SetContentKeyPacketAndSignature(kr *crypto.KeyRing) (*crypto.SessionKey, error) {
	newSessionKey, err := crypto.GenerateSessionKey()
	if err != nil {
		return nil, err
	}

	encSessionKey, err := kr.EncryptSessionKey(newSessionKey)
	if err != nil {
		return nil, err
	}

	sessionKeyPlainMessage := crypto.NewPlainMessage(newSessionKey.Key)
	sessionKeySignature, err := kr.SignDetached(sessionKeyPlainMessage)
	if err != nil {
		return nil, err
	}
	armoredSessionKeySignature, err := sessionKeySignature.GetArmored()
	if err != nil {
		return nil, err
	}

	r.ContentKeyPacket = base64.StdEncoding.EncodeToString(encSessionKey)
	r.ContentKeyPacketSignature = armoredSessionKeySignature
	return newSessionKey, nil
}

type CreateFileRes struct {
	ID         string // Encrypted Link ID
	RevisionID string // Encrypted Revision ID
}

// CreateRevisionRes is the response from creating a new revision.
type CreateRevisionRes struct {
	ID string // Encrypted Revision ID
}

// CommitRevisionReq is the request body for committing a revision.
type CommitRevisionReq struct {
	ManifestSignature string
	SignatureAddress  string
	XAttr             string
}

// SetEncXAttrString encrypts and sets the XAttr field with the provided attributes.
func (r *CommitRevisionReq) SetEncXAttrString(addrKR, nodeKR *crypto.KeyRing, xAttrCommon *RevisionXAttrCommon) error {
	// XAttr has following JSON structure encrypted by node key:
	// {
	//    Common: {
	//        ModificationTime: "2021-09-16T07:40:54+0000",
	//        Size: 13283,
	//        BlockSizes: [1,2,3],
	//        Digests: {"sha1": "..."}
	//    },
	// }

	jsonByteArr, err := json.Marshal(RevisionXAttr{
		Common: *xAttrCommon,
	})
	if err != nil {
		return err
	}

	encXattr, err := nodeKR.Encrypt(crypto.NewPlainMessage(jsonByteArr), addrKR)
	if err != nil {
		return err
	}

	encXattrString, err := encXattr.GetArmored()
	if err != nil {
		return err
	}

	r.XAttr = encXattrString
	return nil
}

type UpdateRevisionReq struct {
	BlockList         []BlockToken
	State             RevisionState
	ManifestSignature string
	SignatureAddress  string
}

type BlockToken struct {
	Index int
	Token string
}
