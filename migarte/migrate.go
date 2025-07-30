package migrate

import (
	"TMS/initializers"
	"TMS/models"
	"log"
)

func CreateDbTables() {

	if initializers.DB == nil {
		log.Fatal("Database connection is nil. Make sure ConnectDB() succeeded.")
	}

	err := initializers.DB.Set("gorm:table_options", "CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci").AutoMigrate(
		&models.User{},
		&models.BlacklistedToken{},
		&models.OTPCode{},
	)

	if err != nil {
		log.Fatal("Failed to migrate database tables:", err)
	}

	log.Println("Database tables migrated successfully")
}
