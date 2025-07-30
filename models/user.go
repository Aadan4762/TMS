package models

import (
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	ID               uuid.UUID `gorm:"primary_key" json:"id"`
	FirstName        string    `gorm:"type:varchar(100)" json:"first_name" validate:"required,min=2,max=100"`
	LastName         string    `gorm:"type:varchar(100)" json:"last_name" validate:"required,min=2,max=100"`
	Email            string    `gorm:"unique;type:varchar(100)" json:"email" validate:"required,email"`
	Password         string    `gorm:"type:varchar(255)" json:"password" validate:"required,min=8"`
	ConfirmPassword  string    `gorm:"-" json:"confirm_password" validate:"required"`
	IsEmailVerified  bool      `gorm:"default:false" json:"is_email_verified"`
	ProfileCompleted bool      `gorm:"default:false" json:"profile_completed"`
	Phone            string    `gorm:"type:varchar(20)" json:"phone"`
	Citizenship      string    `gorm:"type:varchar(20)" json:"citizenship"`
	Sex              string    `gorm:"type:varchar(1)" json:"sex"`
	SNE              string    `gorm:"type:varchar(3)" json:"sne"`
	Role             string    `gorm:"type:varchar(50);default:'user'" json:"role"`
}

func (base *User) BeforeCreate(tx *gorm.DB) error {
	uuid := uuid.NewV4().String()
	tx.Statement.SetColumn("ID", uuid)
	if base.Role == "" {
		tx.Statement.SetColumn("Role", "user")
	}
	return nil
}

func (user *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	return err == nil
}

func (user *User) HasRole(role string) bool {
	return user.Role == role
}

func (user *User) HasAnyRole(roles []string) bool {
	for _, role := range roles {
		if user.Role == role {
			return true
		}
	}
	return false
}
