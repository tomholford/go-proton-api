package proton

import (
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

type CreateFolderReq struct {
	ParentLinkID string

	Name string
	Hash string

	NodeKey     string
	NodeHashKey string

	NodePassphrase          string
	NodePassphraseSignature string

	SignatureAddress string
}

// SetName encrypts and sets the name field.
func (r *CreateFolderReq) SetName(name string, addrKR, nodeKR *crypto.KeyRing) error {
	encNameString, err := getEncryptedName(name, addrKR, nodeKR)
	if err != nil {
		return err
	}

	r.Name = encNameString
	return nil
}

// SetHash computes and sets the hash field.
func (r *CreateFolderReq) SetHash(name string, hashKey []byte) error {
	nameHash, err := GetNameHash(name, hashKey)
	if err != nil {
		return err
	}

	r.Hash = nameHash
	return nil
}

// SetNodeHashKey generates and sets the NodeHashKey field.
func (r *CreateFolderReq) SetNodeHashKey(nodeKR *crypto.KeyRing) error {
	rawHashKey, err := crypto.RandomToken(32)
	if err != nil {
		return err
	}

	encHashKey, err := nodeKR.Encrypt(crypto.NewPlainMessage(rawHashKey), nodeKR)
	if err != nil {
		return err
	}

	encHashKeyString, err := encHashKey.GetArmored()
	if err != nil {
		return err
	}

	r.NodeHashKey = encHashKeyString
	return nil
}

type CreateFolderRes struct {
	ID string // Encrypted Link ID
}

// CheckAvailableHashesReq is the request body for checking available hashes.
type CheckAvailableHashesReq struct {
	Hashes []string
}

// CheckAvailableHashesRes is the response from checking available hashes.
type CheckAvailableHashesRes struct {
	AvailableHashes []string
	PendingHashDtos []PendingHashData `json:"PendingHashDtos,omitempty"`
}

// PendingHashData contains information about pending (draft) uploads.
type PendingHashData struct {
	Hash       string
	RevisionID string
	LinkID     string
	ClientUID  string `json:",omitempty"`
}
