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

type CreateFolderRes struct {
	ID string // Encrypted Link ID
}
