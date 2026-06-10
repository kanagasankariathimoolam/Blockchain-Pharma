package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

const MAX_SPEED = 900.0

type CustodyTransferContract struct {
	contractapi.Contract
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

var temperatureThresholds = map[string][2]float64{
	"default":       {2.0, 8.0},
	"frozen":        {-25.0, -15.0},
	"controlled_rt": {15.0, 25.0},
}

// RegisterDrug registers a new drug into the custodytransfer ledger namespace.
// Must be called before TransferCustody can operate on a drug.
// Parameters match drugregistration chaincode for consistency.
func (c *CustodyTransferContract) RegisterDrug(
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

func (c *CustodyTransferContract) TransferCustody(ctx contractapi.TransactionContextInterface, drugID string, senderID string, receiverID string, iotPayloadJSON string, qrNonce string, location string) error {
	assetJSON, err := ctx.GetStub().GetState(drugID)
	if err != nil || assetJSON == nil {
		return fmt.Errorf("drug %s not found", drugID)
	}
	var asset DrugAsset
	if err := json.Unmarshal(assetJSON, &asset); err != nil {
		return fmt.Errorf("unmarshal failed: %v", err)
	}
	if asset.ComplianceStatus != "COMPLIANT" {
		return fmt.Errorf("asset status is %s not COMPLIANT", asset.ComplianceStatus)
	}
	if asset.CurrentCustodian != senderID {
		return fmt.Errorf("%s is not current custodian", senderID)
	}
	h := sha256.New()
	h.Write([]byte(qrNonce))
	computedHash := fmt.Sprintf("%x", h.Sum(nil))
	if computedHash != asset.QRHash {
		asset.ComplianceStatus = "SUSPECTED_COUNTERFEIT"
		updatedJSON, _ := json.Marshal(asset)
		ctx.GetStub().PutState(drugID, updatedJSON)
		return fmt.Errorf("QR hash mismatch for drug %s", drugID)
	}
	expiry, err := time.Parse("2006-01-02", asset.ExpiryDate)
	if err == nil && time.Now().UTC().After(expiry) {
		asset.ComplianceStatus = "EXPIRED"
		updatedJSON, _ := json.Marshal(asset)
		ctx.GetStub().PutState(drugID, updatedJSON)
		return fmt.Errorf("drug %s expired on %s", drugID, asset.ExpiryDate)
	}
	var iotPayload IoTPayload
	if err := json.Unmarshal([]byte(iotPayloadJSON), &iotPayload); err != nil {
		return fmt.Errorf("invalid IoT payload: %v", err)
	}
	if !validateColdChain(iotPayload, asset.ActiveIngredient) {
		asset.ComplianceStatus = "COLD_CHAIN_BREACH"
		updatedJSON, _ := json.Marshal(asset)
		ctx.GetStub().PutState(drugID, updatedJSON)
		return fmt.Errorf("cold-chain breach temp=%.1f", iotPayload.Temperature)
	}
	if len(asset.CustodyHistory) > 0 {
		last := asset.CustodyHistory[len(asset.CustodyHistory)-1]
		if isGeoImpossible(last, iotPayload) {
			asset.ComplianceStatus = "SUSPECTED_COUNTERFEIT"
			updatedJSON, _ := json.Marshal(asset)
			ctx.GetStub().PutState(drugID, updatedJSON)
			return fmt.Errorf("geographic impossibility for drug %s", drugID)
		}
	}
	event := CustodyEvent{SenderID: senderID, ReceiverID: receiverID, Timestamp: time.Now().UTC().Format(time.RFC3339), IoTPayload: iotPayload, Location: location}
	asset.CustodyHistory = append(asset.CustodyHistory, event)
	asset.ColdChainLog = append(asset.ColdChainLog, iotPayload)
	asset.CurrentCustodian = receiverID
	updatedJSON, err := json.Marshal(asset)
	if err != nil {
		return fmt.Errorf("marshal failed: %v", err)
	}
	return ctx.GetStub().PutState(drugID, updatedJSON)
}

func (c *CustodyTransferContract) QueryDrug(ctx contractapi.TransactionContextInterface, drugID string) (*DrugAsset, error) {
	assetJSON, err := ctx.GetStub().GetState(drugID)
	if err != nil || assetJSON == nil {
		return nil, fmt.Errorf("drug %s not found", drugID)
	}
	var asset DrugAsset
	if err := json.Unmarshal(assetJSON, &asset); err != nil {
		return nil, fmt.Errorf("unmarshal failed: %v", err)
	}
	return &asset, nil
}

func (c *CustodyTransferContract) QueryCustodyHistory(ctx contractapi.TransactionContextInterface, drugID string) ([]CustodyEvent, error) {
	assetJSON, err := ctx.GetStub().GetState(drugID)
	if err != nil || assetJSON == nil {
		return nil, fmt.Errorf("drug %s not found", drugID)
	}
	var asset DrugAsset
	if err := json.Unmarshal(assetJSON, &asset); err != nil {
		return nil, fmt.Errorf("unmarshal failed: %v", err)
	}
	return asset.CustodyHistory, nil
}

func validateColdChain(payload IoTPayload, activeIngredient string) bool {
	thresholds, ok := temperatureThresholds[activeIngredient]
	if !ok {
		thresholds = temperatureThresholds["default"]
	}
	return payload.Temperature >= thresholds[0] && payload.Temperature <= thresholds[1]
}

func isGeoImpossible(lastEvent CustodyEvent, current IoTPayload) bool {
	lastTime, err1 := time.Parse(time.RFC3339, lastEvent.Timestamp)
	currentTime, err2 := time.Parse(time.RFC3339, current.Timestamp)
	if err1 != nil || err2 != nil {
		return false
	}
	distKm := haversineKm(lastEvent.IoTPayload.Latitude, lastEvent.IoTPayload.Longitude, current.Latitude, current.Longitude)
	elapsedHours := currentTime.Sub(lastTime).Hours()
	if elapsedHours <= 0 {
		return distKm > 0.001
	}
	return (distKm / elapsedHours) > MAX_SPEED
}

func haversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371.0
	dLat := (lat2 - lat1) * math.Pi / 180.0
	dLon := (lon2 - lon1) * math.Pi / 180.0
	a := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(lat1*math.Pi/180)*math.Cos(lat2*math.Pi/180)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return R * 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}

func main() {
	chaincode, err := contractapi.NewChaincode(&CustodyTransferContract{})
	if err != nil {
		fmt.Printf("Error creating CustodyTransfer chaincode: %v\n", err)
		return
	}
	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting CustodyTransfer chaincode: %v\n", err)
	}
}
