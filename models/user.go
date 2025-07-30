// models/user.go - Updated User model
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
	IDNumber         string    `gorm:"type:varchar(50)" json:"id_number"`
	PassportNumber   string    `gorm:"type:varchar(50)" json:"passport_number"`
	SNE              string    `gorm:"type:varchar(3)" json:"sne"`
	Designation      string    `gorm:"type:varchar(50)" json:"designation"`
	Role             string    `gorm:"type:varchar(50);default:'user'" json:"role"`

	// Teacher specific fields
	TSCNumber         string `gorm:"type:varchar(50)" json:"tsc_number"`
	SchoolCounty      string `gorm:"type:varchar(100)" json:"school_county"`
	SchoolSubCounty   string `gorm:"type:varchar(100)" json:"school_sub_county"`
	SubjectsInCollege string `gorm:"type:text" json:"subjects_in_college"`
	TeachingSubjects  string `gorm:"type:text" json:"teaching_subjects"`

	// Guest specific fields
	OrganizationName string `gorm:"type:varchar(200)" json:"organization_name"`
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
