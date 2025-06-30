package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type AccountStorage interface {
	Create(account *Account) error
	Read(id string) (*Account, error)
	Update(account *Account) error
	Delete(id string) error
	List() ([]*Account, error)
}

type FilesystemAccountStorage struct {
	dataDir string
}

func NewFilesystemAccountStorage(dataDir string) *FilesystemAccountStorage {
	return &FilesystemAccountStorage{
		dataDir: dataDir,
	}
}

func (fs *FilesystemAccountStorage) Create(account *Account) error {
	if err := os.MkdirAll(fs.dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create accounts directory: %v", err)
	}

	filename := fmt.Sprintf("%d.json", time.Now().UnixNano())
	filePath := filepath.Join(fs.dataDir, filename)

	data, err := json.MarshalIndent(account, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal account: %v", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write account file: %v", err)
	}

	return nil
}

func (fs *FilesystemAccountStorage) Read(id string) (*Account, error) {
	files, err := filepath.Glob(filepath.Join(fs.dataDir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to search account files: %v", err)
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var account Account
		if err := json.Unmarshal(data, &account); err != nil {
			continue
		}

		if account.ID == id {
			return &account, nil
		}
	}

	return nil, fmt.Errorf("account not found: %s", id)
}

func (fs *FilesystemAccountStorage) Update(account *Account) error {
	files, err := filepath.Glob(filepath.Join(fs.dataDir, "*.json"))
	if err != nil {
		return fmt.Errorf("failed to search account files: %v", err)
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var existingAccount Account
		if err := json.Unmarshal(data, &existingAccount); err != nil {
			continue
		}

		if existingAccount.ID == account.ID {
			newData, err := json.MarshalIndent(account, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal account: %v", err)
			}

			if err := os.WriteFile(file, newData, 0644); err != nil {
				return fmt.Errorf("failed to update account file: %v", err)
			}
			return nil
		}
	}

	return fmt.Errorf("account not found for update: %s", account.ID)
}

func (fs *FilesystemAccountStorage) Delete(id string) error {
	files, err := filepath.Glob(filepath.Join(fs.dataDir, "*.json"))
	if err != nil {
		return fmt.Errorf("failed to search account files: %v", err)
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var account Account
		if err := json.Unmarshal(data, &account); err != nil {
			continue
		}

		if account.ID == id {
			if err := os.Remove(file); err != nil {
				return fmt.Errorf("failed to delete account file: %v", err)
			}
			return nil
		}
	}

	return fmt.Errorf("account not found for deletion: %s", id)
}

func (fs *FilesystemAccountStorage) List() ([]*Account, error) {
	files, err := filepath.Glob(filepath.Join(fs.dataDir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to search account files: %v", err)
	}

	var accounts []*Account
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var account Account
		if err := json.Unmarshal(data, &account); err != nil {
			continue
		}

		accounts = append(accounts, &account)
	}

	return accounts, nil
}