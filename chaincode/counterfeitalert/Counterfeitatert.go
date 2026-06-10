package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type CounterfeitAlertContract struct {
	contractapi.Contract
	mu sync.Mutex
}

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
	CreatedAt        string         `json:"createdAt"`
}

type CustodyEvent struct {
	SenderID   string     `json:"senderID"`
	ReceiverID string     `json:"receiverID"`
	Timestamp  string     `json:"timestamp"`
	IoTPayload IoTPayload `json:"iotPayload"`
	Location   string     `json:"location"`
}

type IoTPayload struct {
	Temperature float64 `json:"temperature"`
	Humidity    float64 `json:"humidity"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Timestamp   string  `json:"timestamp"`
	SensorID    string  `json:"sensorID"`
}

type AlertRecord struct {
	DrugID    string `json:"drugID"`
	Reason    string `json:"reason"`
	Timestamp string `json:"timestamp"`
	Location  string `json:"location"`
	Status    string `json:"status"`
}

// RegisterDrug registers a drug into the counterfeitalert ledger namespace.
// Must be called before QueryDrugStatus or alert-based compliance updates work.
func (c *CounterfeitAlertContract) RegisterDrug(
	ctx contractapi.TransactionContextInterface,
	manufacturerID string,
	drugID string,
	expiryDate string,
	activeIngredient string,
	dosageForm string,
	qrNonce string,
) error {
	if manufacturerID == "" || drugID == "" || expiryDate == "" || activeIngredient == "" || dosageForm == "" || qrNonce == "" {
		return fmt.Errorf("all parameters are required")
	}

	existing, err := ctx.GetStub().GetState(drugID)
	if err != nil {
		return fmt.Errorf("failed to read ledger: %v", err)
	}
	if existing != nil {
		return fmt.Errorf("drug %s already exists", drugID)
	}

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
		CreatedAt:        time.Now().UTC().Format(time.RFC3339),
	}

	assetJSON, err := json.Marshal(asset)
	if err != nil {
		return fmt.Errorf("failed to marshal asset: %v", err)
	}

	return ctx.GetStub().PutState(drugID, assetJSON)
}

func (c *CounterfeitAlertContract) RaiseCounterfeitAlert(ctx contractapi.TransactionContextInterface, drugID string, reason string, location string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	assetJSON, err := ctx.GetStub().GetState(drugID)
	if err != nil {
		return fmt.Errorf("failed to read ledger: %v", err)
	}
	if assetJSON != nil {
		var asset DrugAsset
		if err := json.Unmarshal(assetJSON, &asset); err != nil {
			return fmt.Errorf("failed to unmarshal asset: %v", err)
		}
		asset.ComplianceStatus = "SUSPECTED_COUNTERFEIT"
		updatedJSON, err := json.Marshal(asset)
		if err != nil {
			return fmt.Errorf("failed to marshal asset: %v", err)
		}
		if err := ctx.GetStub().PutState(drugID, updatedJSON); err != nil {
			return fmt.Errorf("failed to update asset: %v", err)
		}
	}
	timestamp := time.Now().Format(time.RFC3339)
	alert := AlertRecord{DrugID: drugID, Reason: reason, Timestamp: timestamp, Location: location, Status: "ACTIVE"}
	alertJSON, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("failed to marshal alert: %v", err)
	}
	alertKey := fmt.Sprintf("ALERT_%s_%s", drugID, timestamp)
	if err := ctx.GetStub().PutState(alertKey, alertJSON); err != nil {
		return fmt.Errorf("failed to store alert: %v", err)
	}
	_ = ctx.GetStub().SetEvent("COUNTERFEIT_ALERT", alertJSON)
	return nil
}

func (c *CounterfeitAlertContract) QueryAlerts(ctx contractapi.TransactionContextInterface, drugID string) ([]AlertRecord, error) {
	prefix := fmt.Sprintf("ALERT_%s_", drugID)
	resultsIterator, err := ctx.GetStub().GetStateByRange(prefix, prefix+"~")
	if err != nil {
		return nil, fmt.Errorf("failed to query alerts: %v", err)
	}
	defer resultsIterator.Close()
	var alerts []AlertRecord
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		var alert AlertRecord
		if err := json.Unmarshal(queryResponse.Value, &alert); err != nil {
			continue
		}
		alerts = append(alerts, alert)
	}
	return alerts, nil
}

func (c *CounterfeitAlertContract) QueryDrugStatus(ctx contractapi.TransactionContextInterface, drugID string) (string, error) {
	assetJSON, err := ctx.GetStub().GetState(drugID)
	if err != nil {
		return "", fmt.Errorf("failed to read ledger: %v", err)
	}
	if assetJSON == nil {
		return "", fmt.Errorf("drug %s not found", drugID)
	}
	var asset DrugAsset
	if err := json.Unmarshal(assetJSON, &asset); err != nil {
		return "", fmt.Errorf("failed to unmarshal asset: %v", err)
	}
	return asset.ComplianceStatus, nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&CounterfeitAlertContract{})
	if err != nil {
		fmt.Printf("Error creating CounterfeitAlert chaincode: %v\n", err)
		return
	}
	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting CounterfeitAlert chaincode: %v\n", err)
	}
}
