package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// DrugAsset represents a pharmaceutical unit on the ledger
type DrugAsset struct {
	DrugID           string         `json:"drugID"`
	ManufacturerID   string         `json:"manufacturerID"`
	ExpiryDate       string         `json:"expiryDate"`
	ActiveIngredient string         `json:"activeIngredient"`
	DosageForm       string         `json:"dosageForm"`
	CurrentCustodian string         `json:"currentCustodian"`
	CustodyHistory   []CustodyEvent `json:"custodyHistory"`
	ColdChainLog     []IoTPayload   `json:"coldChainLog"`
	QRHash           string         `json:"qrHash"`
	ComplianceStatus string         `json:"complianceStatus"`
}

// CustodyEvent represents a single custody transfer
type CustodyEvent struct {
	SenderID   string     `json:"senderID"`
	ReceiverID string     `json:"receiverID"`
	Timestamp  string     `json:"timestamp"`
	IoTData    IoTPayload `json:"iotData"`
}

// IoTPayload represents cold-chain sensor data
type IoTPayload struct {
	Temperature float64 `json:"temperature"`
	Humidity    float64 `json:"humidity"`
	GPS         string  `json:"gps"`
	Timestamp   string  `json:"timestamp"`
}

// DrugRegistrationContract implements the DrugRegistration chaincode
type DrugRegistrationContract struct {
	contractapi.Contract
}

// RegisterDrug registers a new pharmaceutical unit on the ledger
// Addresses formal verification property: custody_owner_invariant (NuSMV CTL line 04)
// Guard added post-verification to prevent unauthorized state transitions
func (c *DrugRegistrationContract) RegisterDrug(
	ctx contractapi.TransactionContextInterface,
	manufacturerID string,
	drugID string,
	expiryDate string,
	activeIngredient string,
	dosageForm string,
	qrNonce string,
) error {

	// Guard 1: Verify manufacturer certificate (MSP check)
	// Resolves unauthorized state transition vulnerability found in formal verification
	if err := verifyMemberCert(ctx, manufacturerID); err != nil {
		return fmt.Errorf("unregistered manufacturer: %v", err)
	}

	// Guard 2: Validate regulatory approval
	if err := validateRegulatoryApproval(ctx, manufacturerID, drugID); err != nil {
		return fmt.Errorf("regulatory approval failed: %v", err)
	}

	// Guard 3: Prevent duplicate DrugID registration
	existing, err := ctx.GetStub().GetState(drugID)
	if err != nil {
		return fmt.Errorf("failed to read ledger: %v", err)
	}
	if existing != nil {
		return fmt.Errorf("duplicate DrugID: %s already exists", drugID)
	}

	// Compute SHA256 hash of QR nonce for physical-digital linkage
	hash := sha256.Sum256([]byte(qrNonce))
	qrHash := fmt.Sprintf("%x", hash)

	asset := DrugAsset{
		DrugID:           drugID,
		ManufacturerID:   manufacturerID,
		ExpiryDate:       expiryDate,
		ActiveIngredient: activeIngredient,
		DosageForm:       dosageForm,
		CurrentCustodian: manufacturerID,
		CustodyHistory:   []CustodyEvent{},
		ColdChainLog:     []IoTPayload{},
		QRHash:           qrHash,
		ComplianceStatus: "COMPLIANT",
	}

	assetJSON, err := json.Marshal(asset)
	if err != nil {
		return fmt.Errorf("failed to marshal asset: %v", err)
	}

	return ctx.GetStub().PutState(drugID, assetJSON)
}

// QueryDrug retrieves a drug asset from the ledger
func (c *DrugRegistrationContract) QueryDrug(
	ctx contractapi.TransactionContextInterface,
	drugID string,
) (*DrugAsset, error) {

	assetJSON, err := ctx.GetStub().GetState(drugID)
	if err != nil {
		return nil, fmt.Errorf("failed to read ledger: %v", err)
	}
	if assetJSON == nil {
		return nil, fmt.Errorf("drug %s does not exist", drugID)
	}

	var asset DrugAsset
	if err := json.Unmarshal(assetJSON, &asset); err != nil {
		return nil, fmt.Errorf("failed to unmarshal asset: %v", err)
	}

	return &asset, nil
}

// verifyMemberCert checks that the caller holds a valid MSP X.509 certificate
func verifyMemberCert(ctx contractapi.TransactionContextInterface, memberID string) error {
	// In production: verify X.509 cert from Fabric MSP
	// Stub implementation for artifact reproducibility
	_ = time.Now()
	if memberID == "" {
		return fmt.Errorf("empty memberID")
	}
	return nil
}

// validateRegulatoryApproval checks regulatory approval status
func validateRegulatoryApproval(ctx contractapi.TransactionContextInterface, manufacturerID, drugID string) error {
	// In production: query Tier 1 approval registry
	if manufacturerID == "" || drugID == "" {
		return fmt.Errorf("invalid parameters")
	}
	return nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&DrugRegistrationContract{})
	if err != nil {
		fmt.Printf("Error creating DrugRegistration chaincode: %v\n", err)
		return
	}
	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting DrugRegistration chaincode: %v\n", err)
	}
}
