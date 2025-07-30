package models

import (
	uuid "github.com/satori/go.uuid"
	"gorm.io/gorm"
	"time"
)

type OTPCode struct {
	gorm.Model
	ID        uuid.UUID `gorm:"primary_key" json:"id"`
	Email     string    `gorm:"type:varchar(100)" json:"email"`
	Code      string    `gorm:"type:varchar(6)" json:"code"`
	Purpose   string    `gorm:"type:varchar(50)" json:"purpose"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `gorm:"default:false" json:"used"`
}

func (base *OTPCode) BeforeCreate(tx *gorm.DB) error {
	uuid := uuid.NewV4().String()
	tx.Statement.SetColumn("ID", uuid)
	return nil
}

func (otp *OTPCode) IsExpired() bool {
	return time.Now().After(otp.ExpiresAt)
}

func (otp *OTPCode) IsValid() bool {
	return !otp.Used && !otp.IsExpired()
}

func (otp *OTPCode) MarkAsUsed() {
	otp.Used = true
}
