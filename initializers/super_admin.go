package initializers

import (
	"TMS/models"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os"
)

// CreateSuperAdmin creates a super admin user if it doesn't exist
func CreateSuperAdmin() {
	// Check if super admin already exists
	var existingSuperAdmin models.User
	result := DB.Where("role = ?", "super_admin").First(&existingSuperAdmin)

	if result.Error == nil {
		log.Println("Super admin already exists")
		return
	}

	// Get super admin credentials from environment variables
	superAdminEmail := os.Getenv("SUPER_ADMIN_EMAIL")
	superAdminPassword := os.Getenv("SUPER_ADMIN_PASSWORD")
	superAdminFirstName := os.Getenv("SUPER_ADMIN_FIRST_NAME")
	superAdminLastName := os.Getenv("SUPER_ADMIN_LAST_NAME")

	// Set default values if environment variables are not set
	if superAdminEmail == "" {
		superAdminEmail = "superadmin@tms.com"
	}
	if superAdminPassword == "" {
		superAdminPassword = "SuperAdmin@123"
	}
	if superAdminFirstName == "" {
		superAdminFirstName = "Super"
	}
	if superAdminLastName == "" {
		superAdminLastName = "Admin"
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(superAdminPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("Failed to hash super admin password:", err)
		return
	}

	// Create super admin user
	superAdmin := models.User{
		ID:               uuid.NewV4(),
		FirstName:        superAdminFirstName,
		LastName:         superAdminLastName,
		Email:            superAdminEmail,
		Password:         string(hashedPassword),
		Role:             "super_admin",
		IsEmailVerified:  true,
		ProfileCompleted: true,
	}

	if err := DB.Create(&superAdmin).Error; err != nil {
		log.Fatal("Failed to create super admin:", err)
		return
	}

	log.Printf("Super admin created successfully with email: %s", superAdminEmail)
	log.Printf("Super admin password: %s", superAdminPassword)
	log.Println("Please change the default password after first login!")
}

// SeedDatabase runs all database seeders
func SeedDatabase() {
	log.Println("Starting database seeding...")

	// Create super admin
	CreateSuperAdmin()

	// Add other seeders here if needed
	// CreateDefaultRoles()
	// CreateSampleData()

	log.Println("Database seeding completed!")
}
