package travelrule

import (
	"encoding/json"
	"strings"
	"testing"
)

// The address verification endpoint rejects null for beneficiaryPersons, so a
// nil slice must still marshal to [].
func TestBeneficiaryMarshalsNilPersonsAsEmptyArray(t *testing.T) {
	bs, err := json.Marshal(Beneficiary{AccountNumber: []string{"Taddress"}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(bs)
	if !strings.Contains(got, `"beneficiaryPersons":[]`) {
		t.Errorf("beneficiaryPersons must marshal to [], got %s", got)
	}
	if strings.Contains(got, "null") {
		t.Errorf("output must not contain null, got %s", got)
	}
}

// The same must hold when the Beneficiary is reached through IVMS101, i.e. via
// a pointer field, where a custom marshaller on a value receiver could
// otherwise be bypassed.
func TestBeneficiaryEmptyArrayThroughIVMS101(t *testing.T) {
	bs, err := json.Marshal(IVMS101{Beneficiary: &Beneficiary{AccountNumber: []string{"Taddress"}}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(bs), `"beneficiaryPersons":[]`) {
		t.Errorf("beneficiaryPersons must marshal to [] through IVMS101, got %s", bs)
	}
}

func TestBeneficiaryPreservesPopulatedPersons(t *testing.T) {
	bs, err := json.Marshal(Beneficiary{
		BeneficiaryPersons: []Person{{NaturalPerson: &NaturalPerson{
			Name: &NaturalPersonName{NameIdentifier: []NaturalPersonNameID{{
				PrimaryIdentifier: "Doe", SecondaryIdentifier: "Jane", NameIdentifierType: "LEGL",
			}}},
		}}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(bs), `"primaryIdentifier":"Doe"`) {
		t.Errorf("populated persons were dropped: %s", bs)
	}
}

// Round trip a payload carrying the birth date required by several
// jurisdictions.
func TestIVMS101RoundTrip(t *testing.T) {
	original := IVMS101{
		Originator: &Originator{
			OriginatorPersons: []Person{{NaturalPerson: &NaturalPerson{
				Name: &NaturalPersonName{NameIdentifier: []NaturalPersonNameID{{
					PrimaryIdentifier: "Doe", SecondaryIdentifier: "John",
				}}},
				DateAndPlaceOfBirth: &DateAndPlaceOfBirth{DateOfBirth: "1990-01-02"},
				CountryOfResidence:  "DE",
			}}},
			AccountNumber: []string{"Tfrom"},
		},
		Beneficiary: &Beneficiary{AccountNumber: []string{"Tto"}},
	}
	bs, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded IVMS101
	if err := json.Unmarshal(bs, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Originator == nil || len(decoded.Originator.OriginatorPersons) != 1 {
		t.Fatalf("originator lost in round trip: %s", bs)
	}
	birth := decoded.Originator.OriginatorPersons[0].NaturalPerson.DateAndPlaceOfBirth
	if birth == nil || birth.DateOfBirth != "1990-01-02" {
		t.Errorf("date of birth lost in round trip: %s", bs)
	}
}

// The top level keys are capitalised in the protocol, unlike the nested ones.
func TestIVMS101TopLevelFieldNames(t *testing.T) {
	bs, err := json.Marshal(IVMS101{
		Originator:  &Originator{AccountNumber: []string{"a"}},
		Beneficiary: &Beneficiary{AccountNumber: []string{"b"}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{`"Originator"`, `"Beneficiary"`} {
		if !strings.Contains(string(bs), key) {
			t.Errorf("missing top level key %s in %s", key, bs)
		}
	}
}
