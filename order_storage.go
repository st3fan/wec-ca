package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type OrderStorage interface {
	Create(order *Order) error
	Read(id string) (*Order, error)
	Update(order *Order) error
	Delete(id string) error
	List() ([]*Order, error)
}

type FilesystemOrderStorage struct {
	dataDir string
}

func NewFilesystemOrderStorage(dataDir string) (*FilesystemOrderStorage, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create orders directory: %v", err)
	}
	
	return &FilesystemOrderStorage{
		dataDir: dataDir,
	}, nil
}

func (fs *FilesystemOrderStorage) Create(order *Order) error {
	filename := fmt.Sprintf("%d.json", time.Now().UnixNano())
	filePath := filepath.Join(fs.dataDir, filename)

	data, err := json.MarshalIndent(order, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal order: %v", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write order file: %v", err)
	}

	return nil
}

func (fs *FilesystemOrderStorage) Read(id string) (*Order, error) {
	files, err := filepath.Glob(filepath.Join(fs.dataDir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to search order files: %v", err)
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var order Order
		if err := json.Unmarshal(data, &order); err != nil {
			continue
		}

		if order.ID == id {
			return &order, nil
		}
	}

	return nil, fmt.Errorf("order not found: %s", id)
}

func (fs *FilesystemOrderStorage) Update(order *Order) error {
	files, err := filepath.Glob(filepath.Join(fs.dataDir, "*.json"))
	if err != nil {
		return fmt.Errorf("failed to search order files: %v", err)
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var existingOrder Order
		if err := json.Unmarshal(data, &existingOrder); err != nil {
			continue
		}

		if existingOrder.ID == order.ID {
			newData, err := json.MarshalIndent(order, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal order: %v", err)
			}

			if err := os.WriteFile(file, newData, 0644); err != nil {
				return fmt.Errorf("failed to update order file: %v", err)
			}
			return nil
		}
	}

	return fmt.Errorf("order not found for update: %s", order.ID)
}

func (fs *FilesystemOrderStorage) Delete(id string) error {
	files, err := filepath.Glob(filepath.Join(fs.dataDir, "*.json"))
	if err != nil {
		return fmt.Errorf("failed to search order files: %v", err)
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var order Order
		if err := json.Unmarshal(data, &order); err != nil {
			continue
		}

		if order.ID == id {
			if err := os.Remove(file); err != nil {
				return fmt.Errorf("failed to delete order file: %v", err)
			}
			return nil
		}
	}

	return fmt.Errorf("order not found for deletion: %s", id)
}

func (fs *FilesystemOrderStorage) List() ([]*Order, error) {
	files, err := filepath.Glob(filepath.Join(fs.dataDir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to search order files: %v", err)
	}

	var orders []*Order
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var order Order
		if err := json.Unmarshal(data, &order); err != nil {
			continue
		}

		orders = append(orders, &order)
	}

	return orders, nil
}