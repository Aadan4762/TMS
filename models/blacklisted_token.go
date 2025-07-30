package models

import (
	uuid "github.com/satori/go.uuid"
	"gorm.io/gorm"
	"time"
)

type BlacklistedToken struct {
	gorm.Model
	ID        uuid.UUID `gorm:"primary_key" json:"id"`
	TokenHash string    `gorm:"type:varchar(255)" json:"token_hash"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (base *BlacklistedToken) BeforeCreate(tx *gorm.DB) error {
	uuid := uuid.NewV4().String()
	tx.Statement.SetColumn("ID", uuid)
	return nil
}

func (bt *BlacklistedToken) IsExpired() bool {
	return time.Now().After(bt.ExpiresAt)
}
