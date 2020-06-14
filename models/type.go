package models

// Module : Structure that stores information to be acquired.
type Module struct {
	Name        string
	Title       string
	Discription string   `json:",omitempty"`
	CveIDs      []string `json:",omitempty"`
	EdbIDs      []string `json:",omitempty"`
	References  []string `json:",omitempty"`
}

// Modules :
type Modules []Module