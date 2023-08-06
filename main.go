package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Transaction represents a single transaction in the blockchain
type Transaction struct {
	ID             string
	Sender         string
	SenderPublicKey *rsa.PublicKey // Public key of the sender's identity
	Receiver       string
	Amount         int
	Data           string // Additional data for contract transactions
	Signature      []byte
}

// Block represents a block in the blockchain
type Block struct {
	Index        int
	Timestamp    time.Time
	Transactions []Transaction
	PrevHash     string
	Hash         string
	Nonce        int
}

// Blockchain represents the entire blockchain
type Blockchain struct {
	Blocks          []Block
	TransactionPool []Transaction
	UTXO            map[string][]byte // UTXO model, map of hashed passphrases for each identity
	Identities      map[string]Identity
	mu              sync.Mutex // Mutex for concurrent access to the blockchain data
}

// Identity represents a user's decentralized identity with public and encrypted private keys
type Identity struct {
	PublicKey        *rsa.PublicKey
	EncryptedPrivKey []byte
	OTPEnabled       bool   // Flag to indicate if OTP is enabled
	OTPSecret        string // Secret for generating OTP
	RecoveryPhrase   string // Backup seed phrase for recovery
}

// GenerateIdentity generates a new identity with public and private keys
func GenerateIdentity() (Identity, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		PublicKey:        &privateKey.PublicKey,
		EncryptedPrivKey: nil,
		OTPEnabled:       false,
		OTPSecret:        "",
		RecoveryPhrase:   "",
	}, nil
}

// HashPassphrase generates a cryptographic hash of the passphrase for storage
func HashPassphrase(passphrase string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(passphrase), bcrypt.DefaultCost)
}

// ComparePassphrase compares the provided passphrase with the stored hash
func ComparePassphrase(passphrase string, hash []byte) error {
	return bcrypt.CompareHashAndPassword(hash, []byte(passphrase))
}

// SaveIdentity securely saves the encrypted private key to the identity
func (identity *Identity) SaveIdentity(encryptedPrivKey []byte) {
	identity.EncryptedPrivKey = encryptedPrivKey
}

// GetPrivateKey returns the private key by decrypting it with the provided passphrase
func (identity Identity) GetPrivateKey(passphrase string) (*rsa.PrivateKey, error) {
	return DecryptPrivateKey(identity.EncryptedPrivKey, passphrase)
}

// EnableOTP enables OTP-based multi-factor authentication for the identity
func (identity *Identity) EnableOTP() {
	if identity.OTPEnabled {
		fmt.Println("OTP is already enabled for this identity.")
		return
	}
	identity.OTPEnabled = true
	identity.OTPSecret = generateOTPSecret() // Store the secret for generating OTP
	fmt.Println("OTP enabled successfully.")
}

// generateOTPSecret generates a random secret for OTP
func generateOTPSecret() string {
	secret := make([]byte, 16)
	rand.Read(secret)
	return base32.StdEncoding.EncodeToString(secret)
}

// VerifyOTP verifies the OTP provided by the user
func (identity Identity) VerifyOTP(otp string) bool {
	if !identity.OTPEnabled {
		fmt.Println("OTP is not enabled for this identity.")
		return false
	}
	return verifyOTP(otp, identity.OTPSecret)
}

// verifyOTP verifies the OTP using the secret
func verifyOTP(otp, secret string) bool {
	// Use a library that supports OTP generation and verification (e.g., github.com/hgfischer/go-otp)
	return false
}

// EnableRecoveryPhrase enables backup seed phrase for identity recovery
func (identity *Identity) EnableRecoveryPhrase() {
	if identity.RecoveryPhrase != "" {
		fmt.Println("Recovery phrase is already enabled for this identity.")
		return
	}
	identity.RecoveryPhrase = generateRecoveryPhrase() // Store the recovery phrase
	fmt.Println("Recovery phrase enabled successfully.")
}

// generateRecoveryPhrase generates a random recovery phrase
func generateRecoveryPhrase() string {
	// Generate a random recovery phrase (e.g., 12 or 24 words)
	return "example recovery phrase"
}

// RecoverIdentity recovers the identity using the recovery phrase
func RecoverIdentity(recoveryPhrase, passphrase string) (*Identity, error) {
	// Use the recovery phrase to recover the encrypted private key and create a new identity
	// Use the provided passphrase to decrypt the private key
	return nil, nil
}

const (
	// Other constants remain the same
)

func calculateHash(index int, timestamp time.Time, transactions []Transaction, prevHash string, nonce int) string {
	blockData := strconv.Itoa(index) + timestamp.String() + fmt.Sprintf("%v", transactions) + prevHash + strconv.Itoa(nonce)
	hashInBytes := sha256.Sum256([]byte(blockData))
	return hex.EncodeToString(hashInBytes[:])
}

func generateBlock(prevBlock Block, transactions []Transaction, miner string) Block {
	var newBlock Block
	newBlock.Index = prevBlock.Index + 1
	newBlock.Timestamp = time.Now()
	newBlock.Transactions = transactions
	newBlock.Transactions = append(newBlock.Transactions, createRewardTransaction(miner)) // Add reward transaction
	newBlock.PrevHash = prevBlock.Hash

	// Perform Proof-of-Stake
	nonce := 0
	for {
		newBlock.Hash = calculateHash(newBlock.Index, newBlock.Timestamp, newBlock.Transactions, newBlock.PrevHash, nonce)
		if isBlockValid(newBlock) {
			break
		}
		nonce++
	}

	return newBlock
}

func isBlockValid(block Block) bool {
	targetPrefix := strings.Repeat("0", difficulty)
	return strings.HasPrefix(block.Hash, targetPrefix)
}

func createGenesisBlock() Block {
	genesisBlock := Block{
		Index:        0,
		Timestamp:    time.Now(),
		Transactions: []Transaction{},
		PrevHash:     "0",
		Nonce:        0,
	}

	genesisBlock.Hash = calculateHash(genesisBlock.Index, genesisBlock.Timestamp, genesisBlock.Transactions, genesisBlock.PrevHash, genesisBlock.Nonce)
	return genesisBlock
}

func createRewardTransaction(miner string) Transaction {
	rewardTx := Transaction{
		Sender:   "Reward",
		Receiver: miner,
		Amount:   rewardAmount,
	}
	rewardTx.ID = calculateTransactionHash(rewardTx)
	return rewardTx
}

func calculateTransactionHash(tx Transaction) string {
	txData := tx.Sender + tx.Receiver + strconv.Itoa(tx.Amount)
	txHash := sha256.Sum256([]byte(txData))
	return hex.EncodeToString(txHash[:])
}

func (bc *Blockchain) updateUTXO(transactions []Transaction) {
	for _, tx := range transactions {
		if tx.Sender != "Reward" { // Exclude reward transactions from UTXO
			delete(bc.UTXO, tx.Sender)
		}
		bc.UTXO[tx.Receiver] = tx.SenderPublicKey
	}
}

func (bc *Blockchain) mineBlock(validator Identity) Block {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	newBlock := generateBlock(bc.Blocks[len(bc.Blocks)-1], bc.TransactionPool, validator.PublicKeyToString())

	// Check if the timestamp of the new block is valid
	prevBlock := bc.Blocks[len(bc.Blocks)-1]
	if !validateBlockTimestamp(prevBlock, newBlock) {
		fmt.Println("Invalid block timestamp.")
		return Block{}
	}

	// ... (previous code remains the same)

	return newBlock
}

// ... (previous code remains the same)

var blockchain Blockchain

func main() {
	blockchain = Blockchain{
		Blocks:          []Block{createGenesisBlock()},
		TransactionPool: []Transaction{},
		UTXO:            map[string][]byte{"Alice": nil, "Bob": nil, "Charlie": nil},
		Identities:      map[string]Identity{},
	}

	validators := []Identity{}
	for i := 0; i < 3; i++ {
		identity, err := GenerateIdentity()
		if err != nil {
			fmt.Println("Failed to generate identity:", err)
			os.Exit(1)
		}
		validators = append(validators, identity)
	}

	// Register validators in the blockchain
	for _, validator := range validators {
		blockchain.RegisterIdentity(validator, validator.PublicKeyToString())
	}

	go startServer()

	for {
		miner := validators[0]
		newBlock := blockchain.mineBlock(miner)
		if newBlock.Index != 0 {
			newBlockChannel <- newBlock
		}

		time.Sleep(blockTime * time.Second)
	}
}

// ... (remaining code remains the same)
