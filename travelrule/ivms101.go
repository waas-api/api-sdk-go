// Package travelrule holds the CODE Travel Rule data structures a merchant
// exchanges with the platform.
//
// The IVMS101 payload is encrypted end to end between VASPs. The platform
// never sees it in plaintext, which means it cannot validate or complete these
// structures for you: the completeness of the identity data is the merchant's
// responsibility.
//
// Which fields are required varies by jurisdiction and by the counterparty's
// alliance:
//
//   - Europe and Hong Kong require dateAndPlaceOfBirth.dateOfBirth (YYYY-MM-DD).
//   - GTR requires that date on both Originator and Beneficiary for natural
//     person deposits and withdrawals.
//   - Sygna interoperability additionally requires the originator's
//     customerIdentification, nationalIdentification, geographicAddress and
//     dateAndPlaceOfBirth.
package travelrule

import "encoding/json"

// IVMS101 is the top level identity structure carried inside the encrypted
// payload.
type IVMS101 struct {
	Originator      *Originator      `json:"Originator,omitempty"`
	Beneficiary     *Beneficiary     `json:"Beneficiary,omitempty"`
	OriginatingVASP *OriginatingVASP `json:"OriginatingVASP,omitempty"`
	BeneficiaryVASP *BeneficiaryVASP `json:"BeneficiaryVASP,omitempty"`
}

// Originator is the sending side.
type Originator struct {
	OriginatorPersons []Person `json:"originatorPersons,omitempty"`
	AccountNumber     []string `json:"accountNumber,omitempty"`
}

// Beneficiary is the receiving side. For an address verification the account
// number is what matters and beneficiaryPersons is expected to be an empty
// array.
type Beneficiary struct {
	BeneficiaryPersons []Person `json:"beneficiaryPersons"`
	AccountNumber      []string `json:"accountNumber,omitempty"`
}

// MarshalJSON emits beneficiaryPersons as [] rather than null when the slice is
// nil.
//
// A nil Go slice marshals to null, which the address verification endpoint
// rejects: it requires an empty array. Relying on callers to remember this
// would make the failure intermittent and remote, so it is enforced here.
func (b Beneficiary) MarshalJSON() ([]byte, error) {
	type beneficiaryAlias Beneficiary // break the recursion into this method
	alias := beneficiaryAlias(b)
	if alias.BeneficiaryPersons == nil {
		alias.BeneficiaryPersons = []Person{}
	}
	return json.Marshal(alias)
}

// OriginatingVASP identifies the sending VASP.
type OriginatingVASP struct {
	OriginatingVASP *VASPEntity `json:"originatingVASP,omitempty"`
}

// BeneficiaryVASP identifies the receiving VASP.
type BeneficiaryVASP struct {
	BeneficiaryVASP *VASPEntity `json:"beneficiaryVASP,omitempty"`
}

// Person is either a natural person or a legal person, not both.
type Person struct {
	NaturalPerson *NaturalPerson `json:"naturalPerson,omitempty"`
	LegalPerson   *LegalPerson   `json:"legalPerson,omitempty"`
}

// VASPEntity carries a VASP's legal person details.
type VASPEntity struct {
	LegalPerson *LegalPerson `json:"legalPerson,omitempty"`
}

// NaturalPerson is an individual's identity data.
type NaturalPerson struct {
	Name                   *NaturalPersonName   `json:"name,omitempty"`
	DateAndPlaceOfBirth    *DateAndPlaceOfBirth `json:"dateAndPlaceOfBirth,omitempty"`
	CustomerIdentification string               `json:"customerIdentification,omitempty"`
	CountryOfResidence     string               `json:"countryOfResidence,omitempty"`
}

// NaturalPersonName holds an individual's name identifiers.
type NaturalPersonName struct {
	NameIdentifier      []NaturalPersonNameID `json:"nameIdentifier,omitempty"`
	LocalNameIdentifier []NaturalPersonNameID `json:"localNameIdentifier,omitempty"`
}

// NaturalPersonNameID is a single name identifier.
type NaturalPersonNameID struct {
	PrimaryIdentifier   string `json:"primaryIdentifier"`
	SecondaryIdentifier string `json:"secondaryIdentifier,omitempty"`
	NameIdentifierType  string `json:"nameIdentifierType,omitempty"` // e.g. LEGL
}

// DateAndPlaceOfBirth carries birth details. DateOfBirth uses YYYY-MM-DD.
type DateAndPlaceOfBirth struct {
	DateOfBirth  string `json:"dateOfBirth,omitempty"`
	PlaceOfBirth string `json:"placeOfBirth,omitempty"`
}

// LegalPerson is an organisation's identity data.
type LegalPerson struct {
	Name                   *LegalPersonName        `json:"name,omitempty"`
	GeographicAddress      []GeographicAddress     `json:"geographicAddress,omitempty"`
	NationalIdentification *NationalIdentification `json:"nationalIdentification,omitempty"`
	CountryOfRegistration  string                  `json:"countryOfRegistration,omitempty"`
}

// LegalPersonName holds an organisation's name identifiers.
type LegalPersonName struct {
	NameIdentifier []LegalPersonNameID `json:"nameIdentifier,omitempty"`
}

// LegalPersonNameID is a single organisation name identifier.
type LegalPersonNameID struct {
	LegalPersonName               string `json:"legalPersonName"`
	LegalPersonNameIdentifierType string `json:"legalPersonNameIdentifierType,omitempty"` // e.g. LEGL
}

// GeographicAddress is a postal address.
type GeographicAddress struct {
	AddressType        string   `json:"addressType,omitempty"` // e.g. GEOG
	StreetName         string   `json:"streetName,omitempty"`
	BuildingNumber     string   `json:"buildingNumber,omitempty"`
	BuildingName       string   `json:"buildingName,omitempty"`
	Postcode           string   `json:"postcode,omitempty"`
	TownName           string   `json:"townName,omitempty"`
	AddressLine        []string `json:"addressLine,omitempty"`
	CountrySubDivision string   `json:"countrySubDivision,omitempty"`
	Country            string   `json:"country,omitempty"`
}

// NationalIdentification is a national registration identifier.
type NationalIdentification struct {
	NationalIdentifier     string `json:"nationalIdentifier,omitempty"`
	NationalIdentifierType string `json:"nationalIdentifierType,omitempty"` // e.g. RAID
	RegistrationAuthority  string `json:"registrationAuthority,omitempty"`
}
